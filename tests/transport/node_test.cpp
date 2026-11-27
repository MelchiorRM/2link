// Nodes over loopback TCP: Asio transport, pairing, reconnect and the
// per-peer connection rules (spec v0.1.3 §2.4, §4.6, §4.8, §6.4).

#include "twolink/transport/node.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "twolink/identity/keystore.hpp"
#include "twolink/identity/trust_store.hpp"

namespace {

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using twolink::ErrorCode;
using twolink::crypto::StaticKeyPair;
using twolink::handshake::ConnectionRole;
using twolink::identity::DeviceId;
using twolink::identity::MemoryKeystore;
using twolink::identity::SecretKey;
using twolink::identity::TrustStore;
using twolink::identity::TrustStoreStatus;
using twolink::transport::ClosedInfo;
using twolink::transport::LinkId;
using twolink::transport::Node;
using twolink::transport::NodeObserver;
using twolink::transport::PeerInfo;
using twolink::transport::SasPrompt;

fs::path temp_dir() {
  const SecretKey r = SecretKey::random();
  std::string tag;
  for (std::size_t i = 0; i < 8; ++i) tag += static_cast<char>('a' + r.bytes()[i] % 26);
  return fs::temp_directory_path() / ("2link-node-test-" + tag);
}

// A node plus everything it observed.
struct TestNode {
  TestNode(asio::io_context& io, std::string device_name)
      : dir(temp_dir()), name(std::move(device_name)) {
    EXPECT_EQ(TrustStore::open(keystore, dir / "trust.bin", trust), TrustStoreStatus::kOk);
    NodeObserver obs;
    obs.on_sas = [this](const SasPrompt& p) { sas.push_back(p); };
    obs.on_established = [this](const PeerInfo& p) { established.push_back(p); };
    obs.on_message = [this](const DeviceId& from, const std::string& text) {
      messages.emplace_back(from, text);
    };
    obs.on_closed = [this](const ClosedInfo& c) { closed.push_back(c); };
    node = std::make_unique<Node>(io, key, *trust, this->name, std::move(obs));
  }
  ~TestNode() {
    node.reset();
    std::error_code ec;
    fs::remove_all(dir, ec);
  }

  void listen() {
    ASSERT_FALSE(node->listen({asio::ip::address_v4::loopback(), 0}));
    ASSERT_NE(node->port(), 0);
  }
  [[nodiscard]] asio::ip::tcp::endpoint endpoint() const {
    return {asio::ip::address_v4::loopback(), node->port()};
  }
  [[nodiscard]] DeviceId id() const { return node->device_id(); }
  [[nodiscard]] std::size_t closed_with(ErrorCode code) const {
    std::size_t n = 0;
    for (const ClosedInfo& c : closed) n += c.code == code ? 1 : 0;
    return n;
  }

  fs::path dir;
  std::string name;
  StaticKeyPair key = StaticKeyPair::generate();
  MemoryKeystore keystore;
  std::optional<TrustStore> trust;
  std::unique_ptr<Node> node;

  std::vector<SasPrompt> sas;
  std::vector<PeerInfo> established;
  std::vector<std::pair<DeviceId, std::string>> messages;
  std::vector<ClosedInfo> closed;
};

class NodeTest : public ::testing::Test {
 protected:
  // Runs the event loop until pred() holds; false on timeout.
  bool run_until(const std::function<bool()>& pred, std::chrono::milliseconds timeout = 5s) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (!pred()) {
      if (std::chrono::steady_clock::now() > end) return false;
      io_.restart();
      io_.run_for(5ms);
    }
    return true;
  }
  // Lets pending work settle (closing handshakes, deferred cleanup).
  void settle() { run_until([] { return false; }, 200ms); }

  // b pairs with a (a listens with its window open); both confirm.
  void pair(TestNode& a, TestNode& b) {
    a.node->open_pairing_window();
    const std::size_t sa = a.sas.size();
    const std::size_t sb = b.sas.size();
    const LinkId lb = b.node->pair(a.endpoint());
    ASSERT_TRUE(run_until([&] { return a.sas.size() > sa && b.sas.size() > sb; }));
    ASSERT_EQ(a.sas.back().sas, b.sas.back().sas);
    a.node->confirm_sas(a.sas.back().link);
    b.node->confirm_sas(lb);
    ASSERT_TRUE(run_until([&] { return a.node->connected(b.id()) && b.node->connected(a.id()); }));
  }

  asio::io_context io_;
};

TEST_F(NodeTest, PairThenChat) {
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);

  // Both sides stored each other (§4.7), and the window closed (§4.6).
  ASSERT_TRUE(a.trust->find(b.id()));
  EXPECT_EQ(a.trust->find(b.id())->name, "beta");
  EXPECT_EQ(a.trust->find(b.id())->static_key, b.key.public_key());
  ASSERT_TRUE(b.trust->find(a.id()));
  EXPECT_FALSE(a.node->pairing_gate().window().is_open(twolink::transport::Clock::now()));
  ASSERT_FALSE(a.established.empty());
  EXPECT_TRUE(a.established.back().paired);

  ASSERT_EQ(b.node->send_message(a.id(), "hello alpha"), ErrorCode::kNoError);
  ASSERT_EQ(a.node->send_message(b.id(), "hello beta"), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return !a.messages.empty() && !b.messages.empty(); }));
  EXPECT_EQ(a.messages[0].first, b.id());
  EXPECT_EQ(a.messages[0].second, "hello alpha");
  EXPECT_EQ(b.messages[0].second, "hello beta");
}

TEST_F(NodeTest, LargeMessagesSurviveTcpSegmentation) {
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);
  const std::string big(61440, 'x');  // §6.6 maximum: spans many TCP reads
  for (int i = 0; i < 5; ++i) ASSERT_EQ(b.node->send_message(a.id(), big), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return a.messages.size() == 5; }));
  for (const auto& m : a.messages) EXPECT_EQ(m.second, big);
}

TEST_F(NodeTest, ReconnectAfterPairingNeedsNoSas) {
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);
  b.node->disconnect(a.id());
  ASSERT_TRUE(run_until([&] { return !a.node->connected(b.id()) && !b.node->connected(a.id()); }));
  const std::size_t sas_before = a.sas.size();

  ASSERT_TRUE(b.node->reconnect(a.id(), a.endpoint()));
  ASSERT_TRUE(run_until([&] { return a.node->connected(b.id()) && b.node->connected(a.id()); }));
  EXPECT_EQ(a.sas.size(), sas_before);
  EXPECT_FALSE(a.established.back().paired);
  ASSERT_EQ(b.node->send_message(a.id(), "back"), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return !a.messages.empty(); }));
}

TEST_F(NodeTest, ReconnectToUntrustedPeerIsNotAttempted) {
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  EXPECT_FALSE(b.node->reconnect(a.id(), a.endpoint()));
}

TEST_F(NodeTest, UnknownKeyCannotReconnect) {  // H5
  TestNode a(io_, "alpha");
  TestNode c(io_, "mallory");
  a.listen();
  // c pins a's key, but a has never paired with c.
  ASSERT_EQ(c.trust->add(twolink::identity::make_peer_record(a.key.public_key(), "alpha",
                                                             std::chrono::system_clock::now())),
            TrustStoreStatus::kOk);
  ASSERT_TRUE(c.node->reconnect(a.id(), a.endpoint()));
  ASSERT_TRUE(run_until([&] { return !c.closed.empty() && !a.closed.empty(); }));
  EXPECT_EQ(a.closed.back().code, ErrorCode::kUnknownPeer);
  EXPECT_FALSE(a.node->connected(c.id()));
  EXPECT_TRUE(a.established.empty());
}

TEST_F(NodeTest, PairingOutsideTheWindowIsRefused) {  // H2, §4.6
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  b.node->pair(a.endpoint());
  ASSERT_TRUE(run_until([&] { return !a.closed.empty() && !b.closed.empty(); }));
  EXPECT_TRUE(a.sas.empty());
  EXPECT_TRUE(b.sas.empty());
  EXPECT_FALSE(a.trust->find(b.id()));
}

TEST_F(NodeTest, RejectedSasStoresNothing) {
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  a.node->open_pairing_window();
  const LinkId lb = b.node->pair(a.endpoint());
  ASSERT_TRUE(run_until([&] { return !a.sas.empty() && !b.sas.empty(); }));
  a.node->reject_sas(a.sas.back().link);
  b.node->confirm_sas(lb);
  ASSERT_TRUE(run_until([&] { return !a.closed.empty() && !b.closed.empty(); }));
  EXPECT_EQ(b.closed.back().code, ErrorCode::kPairingRejected);
  EXPECT_FALSE(a.trust->find(b.id()));
  EXPECT_FALSE(b.trust->find(a.id()));
  EXPECT_FALSE(a.node->pairing_gate().awaiting_confirm());  // slot released
}

TEST_F(NodeTest, ConnectionRefusedIsReported) {
  TestNode a(io_, "alpha");
  a.listen();
  const auto ep = a.endpoint();
  a.node->stop();  // nothing listens there now
  TestNode b(io_, "beta");
  b.node->pair(ep);
  ASSERT_TRUE(run_until([&] { return !b.closed.empty(); }));
  EXPECT_TRUE(b.closed.back().transport_lost);
}

TEST_F(NodeTest, BulkNeedsAnEstablishedPrimary) {  // §6.4
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);
  b.node->disconnect(a.id());
  ASSERT_TRUE(run_until([&] { return !a.node->connected(b.id()); }));
  settle();

  const std::size_t a_before = a.closed_with(ErrorCode::kProtocolError);
  const std::size_t b_before = b.closed_with(ErrorCode::kProtocolError);
  ASSERT_TRUE(b.node->reconnect(a.id(), a.endpoint(), ConnectionRole::kBulk));
  // Both sides apply the rule; whichever acts first sends CLOSE, so each end
  // reports PROTOCOL_ERROR, locally or from the peer depending on timing.
  ASSERT_TRUE(run_until([&] {
    return a.closed_with(ErrorCode::kProtocolError) > a_before &&
           b.closed_with(ErrorCode::kProtocolError) > b_before;
  }));
  EXPECT_FALSE(a.node->bulk_link(b.id()));
  EXPECT_FALSE(b.node->bulk_link(a.id()));
}

TEST_F(NodeTest, BulkFollowsItsPrimary) {  // §6.4
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);
  ASSERT_TRUE(b.node->reconnect(a.id(), a.endpoint(), ConnectionRole::kBulk));
  ASSERT_TRUE(run_until([&] { return a.node->bulk_link(b.id()) && b.node->bulk_link(a.id()); }));
  EXPECT_EQ(a.established.back().role, ConnectionRole::kBulk);

  b.node->disconnect(a.id());  // closing the primary closes the bulk connection
  ASSERT_TRUE(run_until([&] {
    return !a.node->bulk_link(b.id()) && !b.node->bulk_link(a.id()) && !a.node->connected(b.id());
  }));
}

TEST_F(NodeTest, SecondPrimaryFromTheSameInitiatorReplacesTheFirst) {  // §6.4
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);
  const LinkId old_a = *a.node->primary_link(b.id());
  ASSERT_TRUE(b.node->reconnect(a.id(), a.endpoint()));
  ASSERT_TRUE(run_until([&] {
    const auto now_a = a.node->primary_link(b.id());
    return now_a && *now_a != old_a && b.closed_with(ErrorCode::kDuplicateConnection) == 1;
  }));
  settle();
  EXPECT_TRUE(a.node->connected(b.id()));
  EXPECT_TRUE(b.node->connected(a.id()));
  ASSERT_EQ(b.node->send_message(a.id(), "still here"), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return !a.messages.empty(); }));
}

TEST_F(NodeTest, CrossedPrimariesKeepTheLowerInitiator) {  // §6.4 tie-break
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  b.listen();
  pair(a, b);  // b initiated this primary
  ASSERT_TRUE(a.node->reconnect(b.id(), b.endpoint()));  // a initiates another
  settle();
  settle();
  // Exactly one primary each side; which one survives depends on the ids.
  ASSERT_TRUE(a.node->connected(b.id()));
  ASSERT_TRUE(b.node->connected(a.id()));
  EXPECT_EQ(a.closed_with(ErrorCode::kDuplicateConnection) +
                b.closed_with(ErrorCode::kDuplicateConnection),
            2u);  // one connection closed, reported on both ends
  ASSERT_EQ(a.node->send_message(b.id(), "x"), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return !b.messages.empty(); }));
}

TEST_F(NodeTest, RePairingWarnsAndReplacesTheOldKey) {  // H4, §4.8
  TestNode a(io_, "alpha");
  a.listen();
  DeviceId old_id{};
  {
    TestNode b(io_, "beta");
    pair(a, b);
    old_id = b.id();
    b.node->stop();
    ASSERT_TRUE(run_until([&] { return !a.node->connected(old_id); }));
  }
  TestNode b2(io_, "beta");  // same name, new key
  a.node->open_pairing_window();
  const LinkId l = b2.node->pair(a.endpoint());
  ASSERT_TRUE(run_until([&] { return a.sas.size() == 2 && !b2.sas.empty(); }));
  EXPECT_EQ(a.sas.back().same_name_as, std::vector<DeviceId>{old_id});  // identity-change warning
  a.node->confirm_sas(a.sas.back().link);
  b2.node->confirm_sas(l);
  ASSERT_TRUE(run_until([&] { return a.node->connected(b2.id()); }));
  EXPECT_FALSE(a.trust->find(old_id));
  EXPECT_TRUE(a.trust->find(b2.id()));
}

}  // namespace
