#pragma once

// Test helpers: a Node with its own trust store that records what it observes,
// and a fixture that runs the event loop until a condition holds.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "twolink/identity/keystore.hpp"
#include "twolink/identity/trust_store.hpp"
#include "twolink/transport/node.hpp"

namespace twolink::test {

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

inline fs::path temp_dir() {
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

}  // namespace twolink::test
