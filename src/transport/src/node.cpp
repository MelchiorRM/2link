#include "twolink/transport/node.hpp"

#include <chrono>
#include <utility>

namespace twolink::transport {

using connection::Event;
using handshake::ConnectionRole;
using handshake::HandshakeKind;
using identity::DeviceId;

Node::Node(asio::io_context& io, const crypto::StaticKeyPair& local, identity::TrustStore& trust,
           std::string device_name, NodeObserver observer)
    : io_(io),
      local_(local),
      trust_(trust),
      device_name_(std::move(device_name)),
      device_id_(identity::device_id_from_key(local.public_key())),
      observer_(std::move(observer)),
      acceptor_(io) {}

Node::~Node() {
  *alive_ = false;
  stop();
}

handshake::HandshakePayload Node::local_payload() const {
  return handshake::HandshakePayload{device_name_, ConnectionRole::kPrimary, 0u};
}

// --- listening --------------------------------------------------------------------

std::error_code Node::listen(const asio::ip::tcp::endpoint& at) {
  std::error_code ec;
  acceptor_.open(at.protocol(), ec);
  if (!ec) acceptor_.set_option(asio::socket_base::reuse_address(true), ec);
  if (!ec) acceptor_.bind(at, ec);
  if (!ec) acceptor_.listen(asio::socket_base::max_listen_connections, ec);
  if (ec) {
    std::error_code ignored;
    acceptor_.close(ignored);
    return ec;
  }
  start_accept();
  return {};
}

std::uint16_t Node::port() const {
  std::error_code ec;
  const auto ep = acceptor_.local_endpoint(ec);
  return ec ? 0 : ep.port();
}

void Node::start_accept() {
  acceptor_.async_accept([this, alive = std::weak_ptr<bool>(alive_)](
                             const std::error_code& ec, asio::ip::tcp::socket socket) {
    const auto token = alive.lock();
    if (!token || !*token) return;
    if (ec) {
      if (ec != asio::error::operation_aborted && acceptor_.is_open()) start_accept();
      return;
    }
    on_accept(std::move(socket));
    start_accept();
  });
}

void Node::on_accept(asio::ip::tcp::socket socket) {
  std::error_code ec;
  const auto remote = socket.remote_endpoint(ec);
  if (ec) return;
  const std::string source = remote.address().to_string();

  auto attempt = std::make_shared<std::optional<connection::PairAttempt>>();
  connection::Hooks hooks;
  hooks.admit_pair = [this, attempt, source]() {
    switch (gate_.admit(source, Clock::now(), *attempt)) {
      case connection::PairingGate::Admit::kAccepted: return ErrorCode::kNoError;
      case connection::PairingGate::Admit::kRateLimited: return ErrorCode::kRateLimited;
      case connection::PairingGate::Admit::kWindowClosed:
      case connection::PairingGate::Admit::kBusy: return ErrorCode::kPairingRejected;
    }
    return ErrorCode::kPairingRejected;
  };
  hooks.is_trusted = [this](const crypto::PublicKey& key) {
    return trust_.find_by_key(key) != nullptr;
  };
  hooks.begin_confirm = [this, attempt]() { return attempt->has_value() && gate_.promote(**attempt); };

  auto link = Link::accept(std::move(socket), local_, local_payload(), std::move(hooks), handler());
  if (link->closed()) return;
  links_.emplace(link->id(), Entry{link, attempt, std::nullopt});
}

void Node::stop() {
  std::error_code ec;
  acceptor_.close(ec);
  auto links = std::exchange(links_, {});
  peers_.clear();
  for (auto& [id, entry] : links) {
    if (entry.attempt && entry.attempt->has_value()) gate_.fail(**entry.attempt, Clock::now());
    entry.link->detach();
  }
}

void Node::open_pairing_window() { gate_.window().open(Clock::now()); }
void Node::close_pairing_window() { gate_.window().close(); }

// --- outgoing ---------------------------------------------------------------------

LinkId Node::pair(const asio::ip::tcp::endpoint& to) {
  auto attempt =
      std::make_shared<std::optional<connection::PairAttempt>>(gate_.begin_outgoing());
  connection::Hooks hooks;
  hooks.begin_confirm = [this, attempt]() { return attempt->has_value() && gate_.promote(**attempt); };
  connection::InitiatorParams params{HandshakeKind::kPair, ConnectionRole::kPrimary, std::nullopt,
                                     connection::random_conn_id()};
  auto link = Link::connect(io_, to, local_, local_payload(), params, std::move(hooks), handler());
  links_.emplace(link->id(), Entry{link, attempt, std::nullopt});
  return link->id();
}

std::optional<LinkId> Node::reconnect(const DeviceId& peer, const asio::ip::tcp::endpoint& to,
                                      ConnectionRole role) {
  const identity::PeerRecord* rec = trust_.find(peer);
  if (!rec) return std::nullopt;  // RECONNECT only to trusted peers (§4.8)
  connection::InitiatorParams params{HandshakeKind::kReconnect, role, rec->static_key,
                                     connection::random_conn_id()};
  auto link = Link::connect(io_, to, local_, local_payload(), params, {}, handler());
  links_.emplace(link->id(), Entry{link, nullptr, peer});
  return link->id();
}

// --- user actions ------------------------------------------------------------------

Link* Node::find(LinkId id) {
  const auto it = links_.find(id);
  return it == links_.end() ? nullptr : it->second.link.get();
}

const Link* Node::find(LinkId id) const {
  const auto it = links_.find(id);
  return it == links_.end() ? nullptr : it->second.link.get();
}

void Node::confirm_sas(LinkId link) {
  if (Link* l = find(link)) l->confirm_sas();
}

void Node::reject_sas(LinkId link) {
  if (Link* l = find(link)) l->reject_sas();
}

ErrorCode Node::send_message(const DeviceId& peer, std::string_view text) {
  const auto id = primary_link(peer);
  Link* l = id ? find(*id) : nullptr;
  return l ? l->send_message(text) : ErrorCode::kInternalError;
}

void Node::disconnect(const DeviceId& peer) {
  if (const auto id = primary_link(peer)) {
    if (Link* l = find(*id)) l->close(ErrorCode::kNoError);  // closes bulk too (§6.4)
  }
}

std::optional<LinkId> Node::primary_link(const DeviceId& peer) const {
  const auto it = peers_.find(peer);
  if (it == peers_.end() || it->second.primary == 0) return std::nullopt;
  return it->second.primary;
}

std::optional<LinkId> Node::bulk_link(const DeviceId& peer) const {
  const auto it = peers_.find(peer);
  if (it == peers_.end() || it->second.bulk == 0) return std::nullopt;
  return it->second.bulk;
}

bool Node::connected(const DeviceId& peer) const {
  const auto id = primary_link(peer);
  const Link* l = id ? find(*id) : nullptr;
  return l && l->state() == connection::State::kEstablished;
}

// --- events -------------------------------------------------------------------------

Link::EventHandler Node::handler() {
  return [this](Link& link, Event event) { on_event(link, std::move(event)); };
}

void Node::on_event(Link& link, Event event) {
  const auto it = links_.find(link.id());
  if (it == links_.end()) return;
  Entry& entry = it->second;

  switch (event.kind) {
    case Event::Kind::kSasReady: {
      const DeviceId id = identity::device_id_from_key(event.peer_key);
      entry.peer = id;
      SasPrompt prompt;
      prompt.link = link.id();
      prompt.sas = event.sas;
      prompt.device_id = id;
      prompt.name = event.peer.device_name;
      for (const identity::PeerRecord* r : trust_.find_by_name(event.peer.device_name)) {
        if (r->device_id != id) prompt.same_name_as.push_back(r->device_id);
      }
      if (observer_.on_sas) observer_.on_sas(prompt);
      return;
    }
    case Event::Kind::kEstablished: on_established(entry, event); return;
    case Event::Kind::kMessage:
      if (entry.peer && observer_.on_message) observer_.on_message(*entry.peer, event.text);
      return;
    case Event::Kind::kFrame: return;  // transfer frames: Phase 2
    case Event::Kind::kClosed: on_closed(link.id(), event); return;
  }
}

void Node::on_established(Entry& entry, const Event& event) {
  const DeviceId peer = identity::device_id_from_key(event.peer_key);
  entry.peer = peer;
  const LinkId id = entry.link->id();

  if (event.paired) {
    const auto now = std::chrono::system_clock::now();
    if (trust_.add(identity::make_peer_record(event.peer_key, event.peer.device_name, now)) !=
        identity::TrustStoreStatus::kOk) {
      entry.link->close(ErrorCode::kInternalError);
      return;
    }
    // Explicit re-pair replaces trusted records with the same name (§4.8).
    std::vector<DeviceId> replaced;
    for (const identity::PeerRecord* r : trust_.find_by_name(event.peer.device_name)) {
      if (r->device_id != peer) replaced.push_back(r->device_id);
    }
    for (const DeviceId& old : replaced) static_cast<void>(trust_.remove(old));
    if (entry.attempt && entry.attempt->has_value()) gate_.succeed(**entry.attempt);
  }

  const ConnectionRole role = entry.link->connection()->role();
  const std::string name = event.peer.device_name;
  const bool paired = event.paired;
  if (!register_link(id, peer, role)) return;
  if (observer_.on_established) observer_.on_established(PeerInfo{id, peer, name, role, paired});
}

DeviceId Node::initiator_of(const Link& link, const DeviceId& peer) const {
  return link.connection()->noise_role() == crypto::Role::kInitiator ? device_id_ : peer;
}

bool Node::register_link(LinkId id, const DeviceId& peer, ConnectionRole role) {
  PeerLinks& pl = peers_[peer];
  Link* self = find(id);

  if (role == ConnectionRole::kBulk) {
    const Link* primary = pl.primary ? find(pl.primary) : nullptr;
    if (!primary || primary->state() != connection::State::kEstablished) {
      self->close(ErrorCode::kProtocolError);  // bulk needs an established primary (§6.4)
      return false;
    }
  }

  LinkId& slot = role == ConnectionRole::kPrimary ? pl.primary : pl.bulk;
  if (slot != 0 && slot != id) {
    Link* existing = find(slot);
    if (existing && !existing->closed()) {
      const DeviceId old_init = initiator_of(*existing, peer);
      const DeviceId new_init = initiator_of(*self, peer);
      // Simultaneous connect: lower initiator device_id wins. Same initiator:
      // the newer connection wins.
      const bool keep_existing = old_init != new_init && connection::initiator_wins(old_init, new_init);
      if (keep_existing) {
        self->close(ErrorCode::kDuplicateConnection);
        return false;
      }
      slot = id;
      existing->close(ErrorCode::kDuplicateConnection);
      return true;
    }
  }
  slot = id;
  return true;
}

void Node::on_closed(LinkId id, const Event& event) {
  auto it = links_.find(id);
  if (it == links_.end()) return;
  Entry& entry = it->second;
  if (entry.attempt && entry.attempt->has_value()) {
    gate_.fail(**entry.attempt, Clock::now());  // no-op if it already succeeded
  }

  ClosedInfo info{id, entry.peer, event.code, event.by_peer, event.transport_lost, event.reason};
  LinkId bulk_to_close = 0;
  if (entry.peer) {
    const auto pit = peers_.find(*entry.peer);
    if (pit != peers_.end()) {
      if (pit->second.primary == id) {
        pit->second.primary = 0;
        bulk_to_close = pit->second.bulk;  // closing the primary closes the bulk (§6.4)
      }
      if (pit->second.bulk == id) pit->second.bulk = 0;
      if (pit->second.primary == 0 && pit->second.bulk == 0) peers_.erase(pit);
    }
  }
  forget_later(id);
  if (observer_.on_closed) observer_.on_closed(info);
  if (bulk_to_close != 0) {
    if (Link* bulk = find(bulk_to_close)) bulk->close(ErrorCode::kNoError);
  }
}

void Node::forget_later(LinkId id) {
  // The Link may be running the callback that got us here: drop it later.
  asio::post(io_, [this, id, alive = std::weak_ptr<bool>(alive_)] {
    const auto token = alive.lock();
    if (token && *token) links_.erase(id);
  });
}

}  // namespace twolink::transport
