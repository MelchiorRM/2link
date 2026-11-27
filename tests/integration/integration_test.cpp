// Phase 1 integration tests over loopback TCP (testing strategy §4: H1, H8,
// H9, H10, S1, S5, L5, Q1). A TcpProxy plays the network attacker.

#include <gtest/gtest.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "tcp_proxy.hpp"
#include "test_node.hpp"
#include "twolink/framing/frame_parser.hpp"

namespace {

using namespace twolink::test;
using Bytes = std::vector<std::uint8_t>;

[[maybe_unused]] bool contains(const Bytes& haystack, std::string_view needle) {
  return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) !=
         haystack.end();
}

[[maybe_unused]] bool contains(const Bytes& haystack, std::span<const std::uint8_t> needle) {
  return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) !=
         haystack.end();
}

// Frames of a captured byte stream.
std::vector<Bytes> frames_of(const Bytes& stream) {
  std::vector<Bytes> out;
  twolink::framing::FrameParser parser;
  static_cast<void>(parser.feed(stream, [&](const twolink::framing::FrameView& f) {
    Bytes frame;
    static_cast<void>(twolink::framing::encode_frame(f.header, f.payload, frame));
    out.push_back(std::move(frame));
  }));
  return out;
}

using Integration = NodeTest;

// --- H8: handshake replay ----------------------------------------------------------

TEST_F(Integration, ReplayedReconnectNeverEstablishes) {  // H8
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);
  b.node->disconnect(a.id());
  ASSERT_TRUE(run_until([&] { return !a.node->connected(b.id()); }));
  settle();

  // b reconnects through the attacker, who records the IK messages.
  TcpProxy proxy(io_, a.endpoint());
  ASSERT_TRUE(b.node->reconnect(a.id(), proxy.endpoint()));
  ASSERT_TRUE(run_until([&] { return a.node->connected(b.id()) && b.node->connected(a.id()); }));
  const auto captured = frames_of(proxy.sent(true, 0));
  ASSERT_FALSE(captured.empty());
  const Bytes ik_message_1 = captured.front();
  const auto established_before = a.established.size();
  const auto live_link = *a.node->primary_link(b.id());

  // Later the attacker replays b's first handshake frame on a new connection.
  asio::ip::tcp::socket attacker(io_);
  attacker.connect(a.endpoint());
  asio::write(attacker, asio::buffer(ik_message_1));
  settle();
  settle();

  // a must not treat the replay as b: no new "established", the real
  // connection survives, and messages still flow.
  EXPECT_EQ(a.established.size(), established_before);
  EXPECT_EQ(a.node->primary_link(b.id()), live_link);
  ASSERT_EQ(b.node->send_message(a.id(), "still the real b"), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return !a.messages.empty(); }));
  EXPECT_EQ(a.messages.back().second, "still the real b");
}

// --- H1: relay attacker during pairing -------------------------------------------

TEST_F(Integration, RelayAttackerGetsTwoDifferentCodes) {  // H1
  // The attacker runs one handshake with b (posing as alpha) and another with
  // a (posing as beta), relaying between them. Two processes: a single device
  // only lets one pairing await confirmation at a time (§4.6).
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  TestNode m_to_b(io_, "alpha");
  TestNode m_to_a(io_, "beta");
  a.listen();
  m_to_b.listen();
  a.node->open_pairing_window();
  m_to_b.node->open_pairing_window();
  b.node->pair(m_to_b.endpoint());  // b thinks it reached alpha
  m_to_a.node->pair(a.endpoint());  // the attacker pairs onward with the real alpha
  ASSERT_TRUE(run_until([&] { return !a.sas.empty() && !b.sas.empty(); }));

  // The two screens the users compare show different codes.
  EXPECT_NE(a.sas.back().sas, b.sas.back().sas);
  EXPECT_EQ(a.sas.back().device_id, m_to_a.id());  // a is really talking to the attacker
  EXPECT_EQ(b.sas.back().device_id, m_to_b.id());

  // The users see the mismatch and reject: neither trusts the attacker.
  a.node->reject_sas(a.sas.back().link);
  b.node->reject_sas(b.sas.back().link);
  ASSERT_TRUE(run_until([&] { return !a.closed.empty() && !b.closed.empty(); }));
  settle();
  EXPECT_TRUE(a.trust->peers().empty());
  EXPECT_TRUE(b.trust->peers().empty());
}

// --- S1: what a passive observer sees ---------------------------------------------

TEST_F(Integration, CapturedTrafficHoldsNoPlaintext) {  // S1
  TestNode a(io_, "alpha-device-name");
  TestNode b(io_, "beta-device-name");
  a.listen();
  TcpProxy tap(io_, a.endpoint());
  a.node->open_pairing_window();
  const LinkId lb = b.node->pair(tap.endpoint());
  ASSERT_TRUE(run_until([&] { return !a.sas.empty() && !b.sas.empty(); }));
  ASSERT_EQ(a.sas.back().sas, b.sas.back().sas);  // a passive relay changes nothing
  a.node->confirm_sas(a.sas.back().link);
  b.node->confirm_sas(lb);
  ASSERT_TRUE(run_until([&] { return a.node->connected(b.id()); }));

  const std::string marker = "PLAINTEXT-MARKER-7f3a9c";
  ASSERT_EQ(b.node->send_message(a.id(), marker), ErrorCode::kNoError);
  ASSERT_EQ(a.node->send_message(b.id(), marker + "-reply"), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return !a.messages.empty() && !b.messages.empty(); }));

  const Bytes wire = tap.all_bytes();
  ASSERT_FALSE(wire.empty());
  EXPECT_FALSE(contains(wire, marker));
  EXPECT_FALSE(contains(wire, "alpha-device-name"));  // names travel encrypted (§4.3)
  EXPECT_FALSE(contains(wire, "beta-device-name"));
  std::string digits = a.sas.back().sas;
  digits.erase(std::remove(digits.begin(), digits.end(), ' '), digits.end());
  EXPECT_FALSE(contains(wire, digits));  // the SAS is never sent
}

// --- S5 / H10: frames moved between connections ------------------------------------

TEST_F(Integration, FrameSplicedFromAnotherPeersConnectionIsRejected) {  // S5, H10
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  TestNode c(io_, "gamma");
  a.listen();
  pair(a, b);
  pair(a, c);
  b.node->disconnect(a.id());
  c.node->disconnect(a.id());
  ASSERT_TRUE(run_until([&] { return !a.node->connected(b.id()) && !a.node->connected(c.id()); }));
  settle();

  // Both reconnect through the attacker, then both chat at once.
  TcpProxy proxy(io_, a.endpoint());
  ASSERT_TRUE(b.node->reconnect(a.id(), proxy.endpoint()));
  ASSERT_TRUE(run_until([&] { return a.node->connected(b.id()); }));
  ASSERT_TRUE(c.node->reconnect(a.id(), proxy.endpoint()));
  ASSERT_TRUE(run_until([&] { return a.node->connected(c.id()); }));
  ASSERT_EQ(b.node->send_message(a.id(), "from b"), ErrorCode::kNoError);
  ASSERT_EQ(c.node->send_message(a.id(), "from c"), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return a.messages.size() == 2; }));
  // Identity comes from each connection's Noise key, never from content (H10).
  for (const auto& [from, text] : a.messages) {
    EXPECT_EQ(text, from == b.id() ? "from b" : "from c");
  }

  // The attacker copies b's last frame into c's connection.
  const auto b_frames = frames_of(proxy.sent(true, 0));
  ASSERT_FALSE(b_frames.empty());
  const std::size_t c_closed = a.closed.size();
  proxy.inject(1, true, b_frames.back());
  ASSERT_TRUE(run_until([&] { return a.closed.size() > c_closed; }));
  EXPECT_EQ(a.closed.back().device_id, c.id());
  EXPECT_EQ(a.closed.back().code, ErrorCode::kProtocolError);  // conn_id mismatch
  EXPECT_EQ(a.messages.size(), 2u);                             // nothing delivered
  EXPECT_TRUE(a.node->connected(b.id()));                       // b unaffected
}

TEST_F(Integration, TamperedFrameClosesWithDecryptFailed) {  // S2 over TCP
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);
  b.node->disconnect(a.id());
  ASSERT_TRUE(run_until([&] { return !a.node->connected(b.id()); }));
  settle();
  TcpProxy proxy(io_, a.endpoint());
  ASSERT_TRUE(b.node->reconnect(a.id(), proxy.endpoint()));
  ASSERT_TRUE(run_until([&] { return a.node->connected(b.id()); }));
  proxy.tamper = [](Bytes& chunk, bool c2s, std::size_t) {
    if (c2s && !chunk.empty()) chunk.back() ^= 0x01;  // flip a bit in the tag
  };
  const std::size_t closed = b.closed.size();
  ASSERT_EQ(b.node->send_message(a.id(), "tampered"), ErrorCode::kNoError);
  ASSERT_TRUE(run_until([&] { return b.closed.size() > closed; }));
  EXPECT_EQ(b.closed.back().code, ErrorCode::kDecryptFailed);  // a's CLOSE reached b
  EXPECT_TRUE(b.closed.back().by_peer);
  EXPECT_TRUE(a.messages.empty());
}

// --- H9: half-open connections --------------------------------------------------------

TEST_F(Integration, HalfOpenConnectionsAreBoundedAndTimeOut) {  // H9
  TestNode a(io_, "alpha");
  a.listen();
  a.node->open_pairing_window();

  // A valid first PAIR message from a real handshake, sent by many sockets
  // that then go silent, plus sockets that never send anything.
  TestNode probe(io_, "probe");
  TcpProxy tap(io_, a.endpoint());
  probe.node->pair(tap.endpoint());
  ASSERT_TRUE(run_until([&] { return !frames_of(tap.sent(true, 0)).empty(); }));
  const Bytes pair_message_1 = frames_of(tap.sent(true, 0)).front();
  probe.node->stop();
  tap.stop();
  settle();
  a.node->pairing_gate().window().close();
  a.node->open_pairing_window();

  std::vector<std::unique_ptr<asio::ip::tcp::socket>> sockets;
  for (int i = 0; i < 20; ++i) {
    auto sock = std::make_unique<asio::ip::tcp::socket>(io_);
    sock->connect(a.endpoint());
    if (i % 2 == 0) asio::write(*sock, asio::buffer(pair_message_1));
    sockets.push_back(std::move(sock));
  }
  settle();
  EXPECT_LE(a.node->pairing_gate().handshaking(), 4u);  // MAX_PAIR_HANDSHAKES
  EXPECT_FALSE(a.node->pairing_gate().awaiting_confirm());
  EXPECT_LE(a.node->link_count(), 4u + 10u);  // 10 silent + admitted PAIR

  // Everything still half-open is gone after HANDSHAKE_TIMEOUT (10 s).
  ASSERT_TRUE(run_until([&] { return a.node->link_count() == 0; }, 13s));
  EXPECT_EQ(a.node->pairing_gate().handshaking(), 0u);
  EXPECT_TRUE(a.sas.empty());
}

// --- Q1: message flood ---------------------------------------------------------------

TEST_F(Integration, MessageFloodIsSlowedNotDropped) {  // Q1
  TestNode a(io_, "alpha");
  TestNode b(io_, "beta");
  a.listen();
  pair(a, b);
  constexpr int kCount = 130;  // limit 50/s: needs at least 3 windows
  const auto start = std::chrono::steady_clock::now();
  for (int i = 0; i < kCount; ++i) {
    ASSERT_EQ(b.node->send_message(a.id(), "m" + std::to_string(i)), ErrorCode::kNoError);
  }
  ASSERT_TRUE(run_until([&] { return a.messages.size() == kCount; }, 10s));
  const auto took = std::chrono::steady_clock::now() - start;
  EXPECT_GE(took, 1800ms);  // back-pressure, not a burst
  for (int i = 0; i < kCount; ++i) {
    EXPECT_EQ(a.messages[static_cast<std::size_t>(i)].second, "m" + std::to_string(i));
  }
  EXPECT_TRUE(a.node->connected(b.id()));  // throttled, not disconnected
}

// --- L5: the library never writes to stdout/stderr --------------------------------------

TEST_F(Integration, LibraryWritesNothingToTheConsole) {  // L5
  std::ostringstream captured_out;
  std::ostringstream captured_err;
  auto* old_out = std::cout.rdbuf(captured_out.rdbuf());
  auto* old_err = std::cerr.rdbuf(captured_err.rdbuf());
  {
    TestNode a(io_, "alpha");
    TestNode b(io_, "beta");
    a.listen();
    pair(a, b);
    static_cast<void>(b.node->send_message(a.id(), "secret text"));
    run_until([&] { return !a.messages.empty(); });
    b.node->disconnect(a.id());
    settle();
  }
  std::cout.rdbuf(old_out);
  std::cerr.rdbuf(old_err);
  // No logging at all means no keys, plaintext or SAS can leak into logs.
  EXPECT_EQ(captured_out.str(), "");
  EXPECT_EQ(captured_err.str(), "");
}

}  // namespace
