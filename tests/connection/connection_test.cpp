// Connection state machine, spec v0.1.2 §6 (threat model H5, H6, H9, S8).

#include "twolink/connection/connection.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include "twolink/connection/payloads.hpp"
#include "twolink/framing/frame_parser.hpp"

namespace {

using namespace std::chrono_literals;
using twolink::ErrorCode;
using twolink::connection::Bytes;
using twolink::connection::Clock;
using twolink::connection::Connection;
using twolink::connection::Event;
using twolink::connection::Hooks;
using twolink::connection::InitiatorParams;
using twolink::connection::State;
using twolink::crypto::PublicKey;
using twolink::crypto::StaticKeyPair;
using twolink::framing::FrameHeader;
using twolink::framing::FrameParser;
using twolink::framing::FrameType;
using twolink::framing::FrameView;
using twolink::handshake::ConnectionRole;
using twolink::handshake::HandshakeKind;
using twolink::handshake::HandshakePayload;

using Kind = Event::Kind;

const Clock::time_point kT0{};
constexpr std::uint64_t kConnId = 0xABCDEF0123456789ull;

struct Frame {
  FrameHeader header;
  Bytes payload;
};

std::vector<Frame> parse(const Bytes& wire) {
  std::vector<Frame> frames;
  FrameParser parser;
  EXPECT_EQ(parser.feed(wire,
                        [&](const FrameView& v) {
                          frames.push_back(
                              Frame{v.header, Bytes(v.payload.begin(), v.payload.end())});
                        }),
            twolink::framing::FrameError::kOk);
  return frames;
}

void deliver(Connection& to, const Bytes& wire, Clock::time_point now, Bytes& reply) {
  for (const Frame& f : parse(wire)) to.on_frame(f.header, f.payload, now, reply);
}

// Moves bytes both ways until both directions are quiet.
void pump(Connection& a, Bytes& a_out, Connection& b, Bytes& b_out, Clock::time_point now) {
  for (int i = 0; i < 20 && (!a_out.empty() || !b_out.empty()); ++i) {
    Bytes to_b = std::exchange(a_out, {});
    deliver(b, to_b, now, b_out);
    Bytes to_a = std::exchange(b_out, {});
    deliver(a, to_a, now, a_out);
  }
}

std::vector<Kind> kinds(const std::vector<Event>& events) {
  std::vector<Kind> k;
  for (const Event& e : events) k.push_back(e.kind);
  return k;
}

// Returns a copy: callers often pass the temporary from take_events().
std::optional<Event> find(const std::vector<Event>& events, Kind kind) {
  for (const Event& e : events) {
    if (e.kind == kind) return e;
  }
  return std::nullopt;
}

Hooks allow_all() {
  Hooks h;
  h.admit_pair = [] { return ErrorCode::kNoError; };
  h.is_trusted = [](const PublicKey&) { return true; };
  h.begin_confirm = [] { return true; };
  return h;
}

struct Node {
  StaticKeyPair key = StaticKeyPair::generate();
  std::string name;
};

struct Pair {
  Node a{StaticKeyPair::generate(), "alpha"};
  Node b{StaticKeyPair::generate(), "beta"};
  std::optional<Connection> ca;  // initiator
  std::optional<Connection> cb;  // responder
  Bytes a_out;
  Bytes b_out;
};

// Starts a connection a -> b; pump() runs the handshake.
void start(Pair& p, HandshakeKind kind, ConnectionRole role = ConnectionRole::kPrimary,
           Hooks a_hooks = allow_all(), Hooks b_hooks = allow_all()) {
  InitiatorParams params{kind, role, std::nullopt, kConnId};
  if (kind == HandshakeKind::kReconnect) params.remote_static = p.b.key.public_key();
  p.ca = Connection::initiate(p.a.key, HandshakePayload{p.a.name, role, 0u}, params,
                              std::move(a_hooks), kT0, p.a_out);
  p.cb = Connection::accept(p.b.key, HandshakePayload{p.b.name, ConnectionRole::kPrimary, 0u},
                            std::move(b_hooks), kT0);
  ASSERT_TRUE(p.ca && p.cb);
  ASSERT_FALSE(p.a_out.empty());
}

void run(Pair& p, Clock::time_point now = kT0) { pump(*p.ca, p.a_out, *p.cb, p.b_out, now); }

// Paired and established.
void established(Pair& p) {
  start(p, HandshakeKind::kPair);
  run(p);
  p.ca->confirm_sas(kT0, p.a_out);
  p.cb->confirm_sas(kT0, p.b_out);
  run(p);
  ASSERT_EQ(p.ca->state(), State::kEstablished);
  ASSERT_EQ(p.cb->state(), State::kEstablished);
  static_cast<void>(p.ca->take_events());
  static_cast<void>(p.cb->take_events());
}

// --- pairing (§4.4-4.5) --------------------------------------------------------

TEST(Connection, PairingShowsTheSameSasThenEstablishes) {
  Pair p;
  start(p, HandshakeKind::kPair);
  run(p);
  ASSERT_EQ(p.ca->state(), State::kAwaitConfirm);
  ASSERT_EQ(p.cb->state(), State::kAwaitConfirm);
  const auto ea = p.ca->take_events();
  const auto eb = p.cb->take_events();
  const std::optional<Event> sa = find(ea, Kind::kSasReady);
  const std::optional<Event> sb = find(eb, Kind::kSasReady);
  ASSERT_TRUE(sa && sb);
  EXPECT_EQ(sa->sas, sb->sas);
  EXPECT_EQ(sa->sas.size(), 7u);
  EXPECT_EQ(sa->peer.device_name, "beta");
  EXPECT_EQ(sb->peer.device_name, "alpha");
  EXPECT_EQ(sa->peer_key, p.b.key.public_key());
  EXPECT_EQ(sb->peer_key, p.a.key.public_key());

  // One side confirming is not enough (§4.5).
  p.ca->confirm_sas(kT0, p.a_out);
  run(p);
  EXPECT_EQ(p.ca->state(), State::kAwaitConfirm);
  EXPECT_EQ(p.cb->state(), State::kAwaitConfirm);
  p.cb->confirm_sas(kT0, p.b_out);
  run(p);
  EXPECT_EQ(p.ca->state(), State::kEstablished);
  EXPECT_EQ(p.cb->state(), State::kEstablished);
  const std::optional<Event> est = find(p.ca->take_events(), Kind::kEstablished);
  ASSERT_TRUE(est);
  EXPECT_TRUE(est->paired);
}

TEST(Connection, MessagesFlowBothWays) {
  Pair p;
  established(p);
  ASSERT_EQ(p.ca->send_message("hello", kT0, p.a_out), ErrorCode::kNoError);
  ASSERT_EQ(p.cb->send_message("caf\xC3\xA9", kT0, p.b_out), ErrorCode::kNoError);
  run(p);
  const auto eb = p.cb->take_events();
  ASSERT_EQ(kinds(eb), std::vector<Kind>{Kind::kMessage});
  EXPECT_EQ(eb[0].text, "hello");
  const auto ea = p.ca->take_events();
  ASSERT_EQ(kinds(ea), std::vector<Kind>{Kind::kMessage});
  EXPECT_EQ(ea[0].text, "caf\xC3\xA9");
}

TEST(Connection, SendMessageChecksStateAndText) {
  Pair p;
  start(p, HandshakeKind::kPair);
  EXPECT_EQ(p.ca->send_message("early", kT0, p.a_out), ErrorCode::kInternalError);
  run(p);
  EXPECT_EQ(p.ca->send_message("unconfirmed", kT0, p.a_out), ErrorCode::kInternalError);
  Pair q;
  established(q);
  EXPECT_EQ(q.ca->send_message("\xFF", kT0, q.a_out), ErrorCode::kProtocolError);
  EXPECT_EQ(q.ca->send_message(std::string(61441, 'x'), kT0, q.a_out), ErrorCode::kProtocolError);
  EXPECT_TRUE(q.a_out.empty());
}

TEST(Connection, RejectingTheSasClosesBothSides) {
  Pair p;
  start(p, HandshakeKind::kPair);
  run(p);
  p.cb->reject_sas(kT0, p.b_out);
  EXPECT_EQ(p.cb->state(), State::kClosing);
  run(p);
  // a received PAIR_REJECT then CLOSE.
  EXPECT_EQ(p.ca->state(), State::kClosed);
  const std::optional<Event> ca = find(p.ca->take_events(), Kind::kClosed);
  ASSERT_TRUE(ca);
  EXPECT_EQ(ca->code, ErrorCode::kPairingRejected);
  EXPECT_TRUE(ca->by_peer);
  // b ends once its CLOSE is flushed.
  p.cb->on_flushed(kT0);
  EXPECT_EQ(p.cb->state(), State::kClosed);
  const std::optional<Event> cb = find(p.cb->take_events(), Kind::kClosed);
  ASSERT_TRUE(cb);
  EXPECT_EQ(cb->code, ErrorCode::kPairingRejected);
  EXPECT_FALSE(cb->by_peer);
}

TEST(Connection, PairingTimesOut) {
  Pair p;
  start(p, HandshakeKind::kPair);
  run(p);
  // Keepalives keep the connection alive while the users decide.
  for (auto t = kT0 + 15s; t < kT0 + 120s; t += 15s) {
    p.ca->on_tick(t, p.a_out);
    p.cb->on_tick(t, p.b_out);
    run(p, t);
    ASSERT_EQ(p.ca->state(), State::kAwaitConfirm);
  }
  p.ca->on_tick(kT0 + 120s, p.a_out);
  EXPECT_EQ(p.ca->state(), State::kClosing);
  run(p, kT0 + 120s);
  const std::optional<Event> cb = find(p.cb->take_events(), Kind::kClosed);
  ASSERT_TRUE(cb);
  EXPECT_EQ(cb->code, ErrorCode::kPairingTimeout);
  EXPECT_TRUE(cb->by_peer);
}

TEST(Connection, SecondPairingCannotAwaitConfirmation) {  // §4.6
  Pair p;
  Hooks busy = allow_all();
  busy.begin_confirm = [] { return false; };
  start(p, HandshakeKind::kPair, ConnectionRole::kPrimary, allow_all(), busy);
  run(p);
  const std::optional<Event> ca = find(p.ca->take_events(), Kind::kClosed);
  ASSERT_TRUE(ca);
  EXPECT_EQ(ca->code, ErrorCode::kPairingRejected);
  EXPECT_FALSE(find(p.cb->take_events(), Kind::kSasReady));
}

// --- refusals before keys (H5, H6, §4.6) -----------------------------------------

TEST(Connection, PairRefusedByTheGateSendsNothing) {
  Pair p;
  Hooks closed = allow_all();
  closed.admit_pair = [] { return ErrorCode::kRateLimited; };
  start(p, HandshakeKind::kPair, ConnectionRole::kPrimary, allow_all(), closed);
  deliver(*p.cb, p.a_out, kT0, p.b_out);
  EXPECT_TRUE(p.b_out.empty());
  EXPECT_EQ(p.cb->state(), State::kClosed);
  const std::optional<Event> e = find(p.cb->take_events(), Kind::kClosed);
  ASSERT_TRUE(e);
  EXPECT_EQ(e->code, ErrorCode::kRateLimited);
}

TEST(Connection, NoHooksMeansNoPairing) {
  Pair p;
  start(p, HandshakeKind::kPair, ConnectionRole::kPrimary, allow_all(), Hooks{});
  deliver(*p.cb, p.a_out, kT0, p.b_out);
  EXPECT_TRUE(p.b_out.empty());
  EXPECT_EQ(p.cb->state(), State::kClosed);
}

TEST(Connection, ReconnectEstablishesWithoutSas) {
  Pair p;
  start(p, HandshakeKind::kReconnect);
  run(p);
  EXPECT_EQ(p.ca->state(), State::kEstablished);
  EXPECT_EQ(p.cb->state(), State::kEstablished);
  const auto eb = p.cb->take_events();
  ASSERT_EQ(kinds(eb), std::vector<Kind>{Kind::kEstablished});
  EXPECT_FALSE(eb[0].paired);
  EXPECT_EQ(eb[0].peer_key, p.a.key.public_key());
}

TEST(Connection, UntrustedReconnectIsDroppedSilently) {  // H5
  Pair p;
  Hooks untrusting = allow_all();
  untrusting.is_trusted = [](const PublicKey&) { return false; };
  start(p, HandshakeKind::kReconnect, ConnectionRole::kPrimary, allow_all(), untrusting);
  deliver(*p.cb, p.a_out, kT0, p.b_out);
  EXPECT_TRUE(p.b_out.empty());
  const std::optional<Event> e = find(p.cb->take_events(), Kind::kClosed);
  ASSERT_TRUE(e);
  EXPECT_EQ(e->code, ErrorCode::kUnknownPeer);
}

TEST(Connection, HandshakeTimesOutSilently) {  // H9
  Pair p;
  start(p, HandshakeKind::kPair);
  EXPECT_EQ(p.cb->next_deadline(), kT0 + 10s);
  p.cb->on_tick(kT0 + 9s, p.b_out);
  EXPECT_EQ(p.cb->state(), State::kHandshaking);
  p.cb->on_tick(kT0 + 10s, p.b_out);
  EXPECT_EQ(p.cb->state(), State::kClosed);
  EXPECT_TRUE(p.b_out.empty());
  EXPECT_EQ(find(p.cb->take_events(), Kind::kClosed)->code, ErrorCode::kTimeout);
}

TEST(Connection, NonHandshakeFrameDuringHandshakeIsDroppedSilently) {  // H6
  Pair p;
  start(p, HandshakeKind::kPair);
  FrameHeader h;
  h.type = FrameType::kPing;
  h.conn_id = kConnId;
  h.length = 24;
  const Bytes payload(24, 0);
  p.cb->on_frame(h, payload, kT0, p.b_out);
  EXPECT_TRUE(p.b_out.empty());
  EXPECT_EQ(p.cb->state(), State::kClosed);
}

// --- keepalive, idle, close (§6.5, §7.1) -----------------------------------------

TEST(Connection, KeepalivePingIsAnswered) {
  Pair p;
  established(p);
  EXPECT_EQ(p.ca->next_deadline(), kT0 + 15s);
  p.ca->on_tick(kT0 + 15s, p.a_out);
  const auto frames = parse(p.a_out);
  ASSERT_EQ(frames.size(), 1u);
  EXPECT_EQ(frames[0].header.type, FrameType::kPing);
  deliver(*p.cb, p.a_out, kT0 + 15s, p.b_out);
  p.a_out.clear();
  ASSERT_EQ(parse(p.b_out).at(0).header.type, FrameType::kPong);
  deliver(*p.ca, p.b_out, kT0 + 15s, p.a_out);
  EXPECT_EQ(p.ca->state(), State::kEstablished);
  EXPECT_TRUE(p.ca->take_events().empty());
}

TEST(Connection, IdlePeerTimesOut) {
  Pair p;
  established(p);
  p.ca->on_tick(kT0 + 45s, p.a_out);  // nothing received for 45 s
  EXPECT_EQ(p.ca->state(), State::kClosing);
  run(p, kT0 + 45s);
  const std::optional<Event> e = find(p.cb->take_events(), Kind::kClosed);
  ASSERT_TRUE(e);
  EXPECT_EQ(e->code, ErrorCode::kTimeout);
  p.ca->on_tick(kT0 + 46s, p.a_out);  // CLOSE_LINGER
  EXPECT_EQ(p.ca->state(), State::kClosed);
}

TEST(Connection, LocalCloseReachesThePeer) {
  Pair p;
  established(p);
  p.ca->close(ErrorCode::kNoError, kT0, p.a_out);
  EXPECT_EQ(p.ca->state(), State::kClosing);
  deliver(*p.cb, p.a_out, kT0, p.b_out);
  EXPECT_TRUE(p.b_out.empty());  // no reply to CLOSE
  EXPECT_EQ(p.cb->state(), State::kClosed);
  const std::optional<Event> e = find(p.cb->take_events(), Kind::kClosed);
  ASSERT_TRUE(e);
  EXPECT_EQ(e->code, ErrorCode::kNoError);
  EXPECT_TRUE(e->by_peer);
  p.ca->on_flushed(kT0);
  EXPECT_EQ(p.ca->state(), State::kClosed);
  EXPECT_FALSE(p.ca->next_deadline());
}

TEST(Connection, TamperedFrameIsReportedWithClose) {  // §7.1
  Pair p;
  established(p);
  ASSERT_EQ(p.ca->send_message("x", kT0, p.a_out), ErrorCode::kNoError);
  p.a_out.back() ^= 1;
  deliver(*p.cb, p.a_out, kT0, p.b_out);
  p.a_out.clear();
  EXPECT_EQ(p.cb->state(), State::kClosing);
  deliver(*p.ca, p.b_out, kT0, p.a_out);
  const std::optional<Event> e = find(p.ca->take_events(), Kind::kClosed);
  ASSERT_TRUE(e);
  EXPECT_EQ(e->code, ErrorCode::kDecryptFailed);
}

TEST(Connection, TransportLoss) {
  Pair p;
  established(p);
  p.ca->on_transport_lost();
  const std::optional<Event> e = find(p.ca->take_events(), Kind::kClosed);
  ASSERT_TRUE(e);
  EXPECT_TRUE(e->transport_lost);
}

TEST(Connection, BulkConnectionCarriesNoMessages) {  // §6.4
  Pair p;
  start(p, HandshakeKind::kReconnect, ConnectionRole::kBulk);
  run(p);
  ASSERT_EQ(p.cb->state(), State::kEstablished);
  EXPECT_EQ(p.cb->role(), ConnectionRole::kBulk);  // taken from the initiator
  EXPECT_EQ(p.ca->send_message("x", kT0, p.a_out), ErrorCode::kInvalidStream);
}

TEST(Connection, BulkCannotPair) {
  Pair p;
  InitiatorParams params{HandshakeKind::kPair, ConnectionRole::kBulk, std::nullopt, kConnId};
  EXPECT_FALSE(Connection::initiate(p.a.key, HandshakePayload{"a", ConnectionRole::kBulk, {}},
                                    params, allow_all(), kT0, p.a_out));
}

// --- per-state and per-role tables (S8) ------------------------------------------

using twolink::connection::allowed_in_state;
using twolink::connection::allowed_on_role;

TEST(FrameRules, StateTable) {
  EXPECT_TRUE(allowed_in_state(State::kHandshaking, FrameType::kHandshake));
  EXPECT_FALSE(allowed_in_state(State::kHandshaking, FrameType::kPing));
  for (FrameType t : {FrameType::kPairConfirm, FrameType::kPairReject, FrameType::kPing,
                      FrameType::kPong, FrameType::kClose}) {
    EXPECT_TRUE(allowed_in_state(State::kAwaitConfirm, t));
  }
  for (FrameType t : {FrameType::kHandshake, FrameType::kRekey, FrameType::kMsg,
                      FrameType::kTransferOffer}) {
    EXPECT_FALSE(allowed_in_state(State::kAwaitConfirm, t));
  }
  for (FrameType t : {FrameType::kHandshake, FrameType::kPairConfirm, FrameType::kPairReject}) {
    EXPECT_FALSE(allowed_in_state(State::kEstablished, t));
  }
  for (FrameType t : {FrameType::kPing, FrameType::kRekey, FrameType::kClose, FrameType::kMsg,
                      FrameType::kChunkData}) {
    EXPECT_TRUE(allowed_in_state(State::kEstablished, t));
  }
  EXPECT_TRUE(allowed_in_state(State::kClosing, FrameType::kClose));
  EXPECT_FALSE(allowed_in_state(State::kClosing, FrameType::kMsg));
  EXPECT_FALSE(allowed_in_state(State::kClosed, FrameType::kClose));
}

TEST(FrameRules, RoleTable) {
  EXPECT_TRUE(allowed_on_role(ConnectionRole::kPrimary, FrameType::kMsg));
  EXPECT_TRUE(allowed_on_role(ConnectionRole::kPrimary, FrameType::kPing));
  EXPECT_FALSE(allowed_on_role(ConnectionRole::kPrimary, FrameType::kChunkData));
  for (FrameType t : {FrameType::kPing, FrameType::kPong, FrameType::kRekey, FrameType::kClose,
                      FrameType::kTransferOffer, FrameType::kChunkData}) {
    EXPECT_TRUE(allowed_on_role(ConnectionRole::kBulk, t));
  }
  for (FrameType t : {FrameType::kMsg, FrameType::kMsgAck, FrameType::kPairConfirm}) {
    EXPECT_FALSE(allowed_on_role(ConnectionRole::kBulk, t));
  }
}

// A peer driven by hand (handshake engine + session), so tests can send frames
// a real Connection never would.
struct RawPeer {
  StaticKeyPair key = StaticKeyPair::generate();
  std::optional<twolink::handshake::HandshakeEngine> engine;
  std::optional<twolink::session::Session> session;

  Bytes seal(FrameType type, std::uint32_t stream, const Bytes& payload) {
    Bytes out;
    EXPECT_EQ(session->seal(kT0, type, stream, payload, out), ErrorCode::kNoError);
    return out;
  }
};

// Runs a handshake from a raw initiator to a Connection responder.
void connect_raw(RawPeer& raw, Connection& conn, HandshakeKind kind, ConnectionRole role,
                 const PublicKey& conn_key) {
  twolink::handshake::EngineConfig ec;
  ec.kind = kind;
  ec.role = twolink::crypto::Role::kInitiator;
  ec.conn_id = kConnId;
  if (kind == HandshakeKind::kReconnect) ec.remote_static = conn_key;
  ec.local_payload = HandshakePayload{"raw", role, {}};
  raw.engine = twolink::handshake::HandshakeEngine::create(ec, raw.key);
  ASSERT_TRUE(raw.engine);
  Bytes to_conn;
  ASSERT_EQ(raw.engine->start(to_conn), ErrorCode::kNoError);
  while (!to_conn.empty()) {
    Bytes to_raw;
    deliver(conn, to_conn, kT0, to_raw);
    to_conn.clear();
    for (const Frame& f : parse(to_raw)) {
      ASSERT_EQ(raw.engine->on_frame(f.header, f.payload, to_conn), ErrorCode::kNoError);
    }
  }
  auto result = raw.engine->take_result();
  ASSERT_TRUE(result);
  raw.session = twolink::session::Session::create(std::move(result->keys), kConnId, kT0);
  ASSERT_TRUE(raw.session);
  if (kind == HandshakeKind::kReconnect) {
    // Key confirmation (§4.8): the IK initiator's first frame; read the PONG.
    Bytes reply;
    deliver(conn, raw.seal(FrameType::kPing, 0, twolink::connection::encode_ping(1)), kT0, reply);
    for (const Frame& f : parse(reply)) {
      Bytes plain;
      ASSERT_EQ(raw.session->open(f.header, f.payload, plain), ErrorCode::kNoError);
    }
  }
}

ErrorCode close_code_after(Connection& conn, RawPeer& raw, const Bytes& wire) {
  Bytes reply;
  deliver(conn, wire, kT0, reply);
  for (const Frame& f : parse(reply)) {
    Bytes plain;
    if (raw.session->open(f.header, f.payload, plain) != ErrorCode::kNoError) continue;
    if (f.header.type == FrameType::kClose) {
      return twolink::connection::decode_close(plain)->code;
    }
  }
  return ErrorCode::kNoError;
}

TEST(FrameRules, MessageBeforePairingIsFatal) {  // S8, §4.5
  RawPeer raw;
  const StaticKeyPair key = StaticKeyPair::generate();
  auto conn = Connection::accept(key, HandshakePayload{"b", ConnectionRole::kPrimary, {}},
                                 allow_all(), kT0);
  connect_raw(raw, *conn, HandshakeKind::kPair, ConnectionRole::kPrimary, key.public_key());
  ASSERT_EQ(conn->state(), State::kAwaitConfirm);
  EXPECT_EQ(close_code_after(*conn, raw, raw.seal(FrameType::kMsg, 1,
                                                  twolink::connection::encode_msg("hi"))),
            ErrorCode::kProtocolError);
  EXPECT_EQ(conn->state(), State::kClosing);
}

TEST(FrameRules, PairConfirmAfterReconnectIsFatal) {  // S8
  RawPeer raw;
  const StaticKeyPair key = StaticKeyPair::generate();
  auto conn = Connection::accept(key, HandshakePayload{"b", ConnectionRole::kPrimary, {}},
                                 allow_all(), kT0);
  connect_raw(raw, *conn, HandshakeKind::kReconnect, ConnectionRole::kPrimary, key.public_key());
  ASSERT_EQ(conn->state(), State::kEstablished);
  EXPECT_EQ(close_code_after(*conn, raw, raw.seal(FrameType::kPairConfirm, 0, {})),
            ErrorCode::kProtocolError);
}

TEST(FrameRules, TransferFrameOnPrimaryIsInvalidStream) {  // §6.4
  RawPeer raw;
  const StaticKeyPair key = StaticKeyPair::generate();
  auto conn = Connection::accept(key, HandshakePayload{"b", ConnectionRole::kPrimary, {}},
                                 allow_all(), kT0);
  connect_raw(raw, *conn, HandshakeKind::kReconnect, ConnectionRole::kPrimary, key.public_key());
  EXPECT_EQ(close_code_after(*conn, raw, raw.seal(FrameType::kTransferOffer, 2, {1, 2, 3})),
            ErrorCode::kInvalidStream);
}

TEST(FrameRules, MessageOnBulkIsInvalidStream) {  // §6.4
  RawPeer raw;
  const StaticKeyPair key = StaticKeyPair::generate();
  auto conn = Connection::accept(key, HandshakePayload{"b", ConnectionRole::kPrimary, {}},
                                 allow_all(), kT0);
  connect_raw(raw, *conn, HandshakeKind::kReconnect, ConnectionRole::kBulk, key.public_key());
  EXPECT_EQ(close_code_after(*conn, raw,
                             raw.seal(FrameType::kMsg, 1, twolink::connection::encode_msg("x"))),
            ErrorCode::kInvalidStream);
}

TEST(FrameRules, TransferFrameOnBulkIsPassedUp) {
  RawPeer raw;
  const StaticKeyPair key = StaticKeyPair::generate();
  auto conn = Connection::accept(key, HandshakePayload{"b", ConnectionRole::kPrimary, {}},
                                 allow_all(), kT0);
  connect_raw(raw, *conn, HandshakeKind::kReconnect, ConnectionRole::kBulk, key.public_key());
  static_cast<void>(conn->take_events());
  Bytes reply;
  deliver(*conn, raw.seal(FrameType::kTransferOffer, 7, {1, 2, 3}), kT0, reply);
  const auto events = conn->take_events();
  ASSERT_EQ(kinds(events), std::vector<Kind>{Kind::kFrame});
  EXPECT_EQ(events[0].type, FrameType::kTransferOffer);
  EXPECT_EQ(events[0].stream_id, 7u);
  EXPECT_EQ(events[0].payload, (Bytes{1, 2, 3}));
}

TEST(FrameRules, MalformedControlPayloadIsFatal) {
  RawPeer raw;
  const StaticKeyPair key = StaticKeyPair::generate();
  auto conn = Connection::accept(key, HandshakePayload{"b", ConnectionRole::kPrimary, {}},
                                 allow_all(), kT0);
  connect_raw(raw, *conn, HandshakeKind::kReconnect, ConnectionRole::kPrimary, key.public_key());
  EXPECT_EQ(close_code_after(*conn, raw, raw.seal(FrameType::kPing, 0, {1, 2, 3})),
            ErrorCode::kProtocolError);
}

// --- IK key confirmation (§4.8, threat model H8) ------------------------------------

TEST(KeyConfirmation, ResponderWaitsForTheInitiatorsFirstFrame) {
  const StaticKeyPair key = StaticKeyPair::generate();
  RawPeer raw;
  twolink::handshake::EngineConfig ec;
  ec.kind = HandshakeKind::kReconnect;
  ec.role = twolink::crypto::Role::kInitiator;
  ec.conn_id = kConnId;
  ec.remote_static = key.public_key();
  ec.local_payload = HandshakePayload{"raw", ConnectionRole::kPrimary, {}};
  raw.engine = twolink::handshake::HandshakeEngine::create(ec, raw.key);
  Bytes msg1;
  ASSERT_EQ(raw.engine->start(msg1), ErrorCode::kNoError);

  // A replay: IK message 1 arrives, the initiator never follows up.
  auto conn = Connection::accept(key, HandshakePayload{"b", ConnectionRole::kPrimary, {}},
                                 allow_all(), kT0);
  Bytes msg2;
  deliver(*conn, msg1, kT0, msg2);
  EXPECT_FALSE(msg2.empty());                    // message 2 is sent...
  EXPECT_EQ(conn->state(), State::kHandshaking);  // ...but nothing is established
  EXPECT_TRUE(conn->take_events().empty());
  Bytes later;
  conn->on_tick(kT0 + 10s, later);
  EXPECT_TRUE(later.empty());  // closes silently at HANDSHAKE_TIMEOUT
  EXPECT_EQ(conn->state(), State::kClosed);
}

TEST(KeyConfirmation, GarbageInsteadOfTheFirstFrameClosesSilently) {
  RawPeer raw;
  const StaticKeyPair key = StaticKeyPair::generate();
  auto conn = Connection::accept(key, HandshakePayload{"b", ConnectionRole::kPrimary, {}},
                                 allow_all(), kT0);
  twolink::handshake::EngineConfig ec;
  ec.kind = HandshakeKind::kReconnect;
  ec.role = twolink::crypto::Role::kInitiator;
  ec.conn_id = kConnId;
  ec.remote_static = key.public_key();
  ec.local_payload = HandshakePayload{"raw", ConnectionRole::kPrimary, {}};
  raw.engine = twolink::handshake::HandshakeEngine::create(ec, raw.key);
  Bytes msg1;
  ASSERT_EQ(raw.engine->start(msg1), ErrorCode::kNoError);
  Bytes msg2;
  deliver(*conn, msg1, kT0, msg2);
  FrameHeader h;
  h.type = FrameType::kPing;
  h.conn_id = kConnId;
  h.length = 8 + 16;
  Bytes reply;
  conn->on_frame(h, Bytes(24, 0x55), kT0, reply);
  EXPECT_TRUE(reply.empty());  // no CLOSE to an unconfirmed peer
  EXPECT_EQ(conn->state(), State::kClosed);
  const auto e = find(conn->take_events(), Kind::kClosed);
  ASSERT_TRUE(e);
  EXPECT_EQ(e->code, ErrorCode::kHandshakeFailed);
}

TEST(KeyConfirmation, InitiatorSendsPingAtOnce) {
  Pair p;
  start(p, HandshakeKind::kReconnect);
  // Deliver a's message 1, then b's message 2 back to a.
  Bytes msg2;
  deliver(*p.cb, p.a_out, kT0, msg2);
  Bytes confirm;
  deliver(*p.ca, msg2, kT0, confirm);
  EXPECT_EQ(p.ca->state(), State::kEstablished);
  const auto frames = parse(confirm);
  ASSERT_EQ(frames.size(), 1u);
  EXPECT_EQ(frames[0].header.type, FrameType::kPing);
  Bytes pong;
  deliver(*p.cb, confirm, kT0, pong);
  EXPECT_EQ(p.cb->state(), State::kEstablished);
}

// --- simultaneous connect (§6.4) --------------------------------------------------

TEST(FrameRules, LowerInitiatorDeviceIdWins) {
  twolink::identity::DeviceId low{};
  twolink::identity::DeviceId high{};
  high[31] = 1;  // differs only in the last byte: all 32 bytes count (§4.1)
  EXPECT_TRUE(twolink::connection::initiator_wins(low, high));
  EXPECT_FALSE(twolink::connection::initiator_wins(high, low));
}

}  // namespace
