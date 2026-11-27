// Discovery over loopback UDP, spec v0.1.3 §8 (threat model D1, D3), and the
// D1 integration check: a forged announcement never leads to trust.

#include "twolink/discovery/service.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "twolink/core/tlv.hpp"
#include "twolink/crypto/keys.hpp"
#include "twolink/identity/keystore.hpp"
#include "twolink/identity/trust_store.hpp"
#include "twolink/transport/node.hpp"

namespace {

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using namespace twolink::discovery;
using twolink::crypto::StaticKeyPair;
using twolink::identity::DeviceId;

asio::ip::udp::endpoint loopback(std::uint16_t port) {
  return {asio::ip::address_v4::loopback(), port};
}

ServiceConfig test_config() {
  ServiceConfig c;
  c.bind_address = asio::ip::address_v4::loopback();
  c.listen_port = 0;  // any free port
  c.broadcast = false;
  c.interval = 100ms;
  return c;
}

class DiscoveryTest : public ::testing::Test {
 protected:
  bool run_until(const std::function<bool()>& pred, std::chrono::milliseconds timeout = 5s) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (!pred()) {
      if (std::chrono::steady_clock::now() > end) return false;
      io_.restart();
      io_.run_for(5ms);
    }
    return true;
  }
  asio::io_context io_;
};

TEST_F(DiscoveryTest, TwoServicesFindEachOther) {
  const StaticKeyPair ka = StaticKeyPair::generate();
  const StaticKeyPair kb = StaticKeyPair::generate();
  std::vector<DiscoveredDevice> new_on_a;
  DiscoveryService a(io_, make_announcement("alpha", ka.public_key(), 1111), test_config(), {},
                     [&](const DiscoveredDevice& d) { new_on_a.push_back(d); });
  DiscoveryService b(io_, make_announcement("beta", kb.public_key(), 2222), test_config());
  ASSERT_FALSE(a.start());
  ASSERT_FALSE(b.start());
  a.add_target(loopback(b.port()));
  b.add_target(loopback(a.port()));
  a.add_target(loopback(a.port()));  // its own announcement must be ignored

  const DeviceId ida = twolink::identity::device_id_from_key(ka.public_key());
  const DeviceId idb = twolink::identity::device_id_from_key(kb.public_key());
  ASSERT_TRUE(run_until([&] {
    return a.table().find(idb, Clock::now()) && b.table().find(ida, Clock::now());
  }));
  const auto seen = a.table().find(idb, Clock::now());
  EXPECT_EQ(seen->announcement.device_name, "beta");
  EXPECT_EQ(seen->announcement.tcp_port, 2222);
  EXPECT_EQ(seen->address, "127.0.0.1");
  EXPECT_FALSE(a.table().find(ida, Clock::now()));  // not itself
  ASSERT_EQ(new_on_a.size(), 1u);                   // reported once, not on every refresh
  run_until([] { return false; }, 300ms);
  EXPECT_EQ(new_on_a.size(), 1u);
}

TEST_F(DiscoveryTest, GarbageDatagramsAreDropped) {  // D3
  DiscoveryService a(io_, make_announcement("alpha", StaticKeyPair::generate().public_key(), 1),
                     test_config());
  ASSERT_FALSE(a.start());
  asio::ip::udp::socket sender(io_, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0));
  const std::vector<std::vector<std::uint8_t>> junk{
      {}, {'2', 'L', 'N', 'K'}, std::vector<std::uint8_t>(600, 0x41), {'2', 'L', 'N', 'K', 1, 1, 0x80, 0, 0}};
  for (const auto& d : junk) sender.send_to(asio::buffer(d), loopback(a.port()));
  ASSERT_TRUE(run_until([&] { return a.dropped() >= junk.size() - 1; }));  // empty may not arrive
  EXPECT_EQ(a.table().size(), 0u);
}

TEST_F(DiscoveryTest, ForgedAnnouncementNeverGainsTrust) {  // D1
  // a has paired with b. m announces b's name with its own key, and the TCP
  // port of m's own node.
  const auto r = twolink::identity::SecretKey::random();
  std::string tag;
  for (std::size_t i = 0; i < 8; ++i) tag += static_cast<char>('a' + r.bytes()[i] % 26);
  const fs::path dir = fs::temp_directory_path() / ("2link-d1-" + tag);

  twolink::identity::MemoryKeystore ks_a;
  twolink::identity::MemoryKeystore ks_m;
  std::optional<twolink::identity::TrustStore> trust_a;
  std::optional<twolink::identity::TrustStore> trust_m;
  ASSERT_EQ(twolink::identity::TrustStore::open(ks_a, dir / "a.bin", trust_a),
            twolink::identity::TrustStoreStatus::kOk);
  ASSERT_EQ(twolink::identity::TrustStore::open(ks_m, dir / "m.bin", trust_m),
            twolink::identity::TrustStoreStatus::kOk);
  const StaticKeyPair ka = StaticKeyPair::generate();
  const StaticKeyPair kb = StaticKeyPair::generate();
  const StaticKeyPair km = StaticKeyPair::generate();
  ASSERT_EQ(trust_a->add(twolink::identity::make_peer_record(kb.public_key(), "beta",
                                                             std::chrono::system_clock::now())),
            twolink::identity::TrustStoreStatus::kOk);
  const DeviceId idb = twolink::identity::device_id_from_key(kb.public_key());
  const DeviceId idm = twolink::identity::device_id_from_key(km.public_key());

  std::vector<twolink::transport::ClosedInfo> a_closed;
  twolink::transport::NodeObserver obs;
  obs.on_closed = [&](const twolink::transport::ClosedInfo& c) { a_closed.push_back(c); };
  twolink::transport::Node node_a(io_, ka, *trust_a, "alpha", obs);
  twolink::transport::Node node_m(io_, km, *trust_m, "beta", {});
  ASSERT_FALSE(node_m.listen({asio::ip::address_v4::loopback(), 0}));

  DiscoveryService disc_a(io_, make_announcement("alpha", ka.public_key(), 1), test_config());
  DiscoveryService disc_m(io_, make_announcement("beta", km.public_key(), node_m.port()),
                          test_config());
  ASSERT_FALSE(disc_a.start());
  ASSERT_FALSE(disc_m.start());
  disc_m.add_target(loopback(disc_a.port()));
  ASSERT_TRUE(run_until([&] { return disc_a.table().find(idm, Clock::now()).has_value(); }));

  // Shown as unverified, with the name-clash warning.
  const auto forged = disc_a.table().find(idm, Clock::now());
  EXPECT_EQ(classify(forged->announcement, *trust_a), DeviceStatus::kUnverifiedNameClash);

  // Reconnecting to "beta" at the forged address pins b's real key: IK fails.
  const asio::ip::tcp::endpoint at(asio::ip::make_address(forged->address),
                                   forged->announcement.tcp_port);
  ASSERT_TRUE(node_a.reconnect(idb, at));
  ASSERT_TRUE(run_until([&] { return !a_closed.empty(); }));
  EXPECT_FALSE(node_a.connected(idb));
  EXPECT_FALSE(node_a.connected(idm));
  ASSERT_EQ(trust_a->peers().size(), 1u);  // trust store unchanged
  EXPECT_EQ(trust_a->peers()[0].device_id, idb);

  node_a.stop();
  node_m.stop();
  std::error_code ec;
  fs::remove_all(dir, ec);
}

}  // namespace
