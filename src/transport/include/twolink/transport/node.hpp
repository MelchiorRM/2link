#pragma once

// A 2Link node: listener, outgoing connections, pairing gate, trust store and
// the per-peer connection rules of spec v0.1.3 §6.4.
//
// - Incoming PAIR goes through the PairingGate (window, limits, rate limiter,
//   §4.6); outgoing PAIR is an explicit call and takes only the confirm slot.
// - Incoming RECONNECT is accepted only for keys in the trust store (§4.8).
// - A successful pairing stores the peer, replacing trusted records with the
//   same name (the explicit re-pair of §4.8), and closes the pairing window.
// - Per peer: at most one primary and one bulk connection. A duplicate is
//   resolved by the lower initiator device_id; if both connections have the
//   same initiator, the newer one wins (the older is presumed stale). A bulk
//   connection needs an established primary; closing the primary closes it.
//
// Threading: like Link, everything runs on the io_context's thread.

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <asio.hpp>

#include "twolink/connection/pairing_gate.hpp"
#include "twolink/identity/device_id.hpp"
#include "twolink/identity/trust_store.hpp"
#include "twolink/transport/link.hpp"

namespace twolink::transport {

// §9.
inline constexpr std::uint16_t kDefaultTcpPort = 47821;

using LinkId = std::uint64_t;

struct SasPrompt {
  LinkId link = 0;
  std::string sas;  // "123 456"
  identity::DeviceId device_id{};
  std::string name;
  // Trusted peers with the same name but another key: show an identity-change
  // warning (§4.8, IDENTITY_CHANGED). Confirming replaces them.
  std::vector<identity::DeviceId> same_name_as;
};

struct PeerInfo {
  LinkId link = 0;
  identity::DeviceId device_id{};
  std::string name;
  handshake::ConnectionRole role = handshake::ConnectionRole::kPrimary;
  bool paired = false;  // true: just paired; false: reconnected
};

struct ClosedInfo {
  LinkId link = 0;
  std::optional<identity::DeviceId> device_id;  // known once the handshake finished
  ErrorCode code = ErrorCode::kNoError;
  bool by_peer = false;
  bool transport_lost = false;
  std::string reason;
};

struct NodeObserver {
  std::function<void(const SasPrompt&)> on_sas;
  std::function<void(const PeerInfo&)> on_established;
  std::function<void(const identity::DeviceId&, const std::string& text)> on_message;
  std::function<void(const ClosedInfo&)> on_closed;
};

class Node {
 public:
  // `local` and `trust` must outlive the Node.
  Node(asio::io_context& io, const crypto::StaticKeyPair& local, identity::TrustStore& trust,
       std::string device_name, NodeObserver observer);
  ~Node();

  Node(const Node&) = delete;
  Node& operator=(const Node&) = delete;

  // Starts accepting on `at` (port 0 picks a free port).
  [[nodiscard]] std::error_code listen(const asio::ip::tcp::endpoint& at);
  [[nodiscard]] std::uint16_t port() const;
  // Closes the listener and every connection.
  void stop();

  // The local pairing window (§4.6).
  void open_pairing_window();
  void close_pairing_window();

  // Outgoing PAIR to `to` (explicit user action).
  LinkId pair(const asio::ip::tcp::endpoint& to);
  // Outgoing RECONNECT to a trusted peer; nullopt if `peer` is not trusted.
  std::optional<LinkId> reconnect(const identity::DeviceId& peer, const asio::ip::tcp::endpoint& to,
                                  handshake::ConnectionRole role = handshake::ConnectionRole::kPrimary);

  void confirm_sas(LinkId link);
  void reject_sas(LinkId link);

  // Over the peer's primary connection. kInternalError if not connected.
  [[nodiscard]] ErrorCode send_message(const identity::DeviceId& peer, std::string_view text);
  void disconnect(const identity::DeviceId& peer);

  [[nodiscard]] bool connected(const identity::DeviceId& peer) const;
  [[nodiscard]] std::optional<LinkId> primary_link(const identity::DeviceId& peer) const;
  [[nodiscard]] std::optional<LinkId> bulk_link(const identity::DeviceId& peer) const;
  [[nodiscard]] std::size_t link_count() const noexcept { return links_.size(); }
  [[nodiscard]] const identity::DeviceId& device_id() const noexcept { return device_id_; }
  [[nodiscard]] connection::PairingGate& pairing_gate() noexcept { return gate_; }

 private:
  struct Entry {
    std::shared_ptr<Link> link;
    std::shared_ptr<std::optional<connection::PairAttempt>> attempt;
    std::optional<identity::DeviceId> peer;
  };
  struct PeerLinks {
    LinkId primary = 0;
    LinkId bulk = 0;
  };

  void start_accept();
  void on_accept(asio::ip::tcp::socket socket);
  Link::EventHandler handler();
  void on_event(Link& link, connection::Event event);
  void on_established(Entry& entry, const connection::Event& event);
  // Applies §6.4; false if this link lost and is being closed.
  bool register_link(LinkId id, const identity::DeviceId& peer, handshake::ConnectionRole role);
  void on_closed(LinkId id, const connection::Event& event);
  [[nodiscard]] identity::DeviceId initiator_of(const Link& link,
                                                const identity::DeviceId& peer) const;
  [[nodiscard]] handshake::HandshakePayload local_payload() const;
  Link* find(LinkId id);
  const Link* find(LinkId id) const;
  void forget_later(LinkId id);

  asio::io_context& io_;
  const crypto::StaticKeyPair& local_;
  identity::TrustStore& trust_;
  std::string device_name_;
  identity::DeviceId device_id_;
  NodeObserver observer_;
  asio::ip::tcp::acceptor acceptor_;
  connection::PairingGate gate_;
  std::map<LinkId, Entry> links_;
  std::map<identity::DeviceId, PeerLinks> peers_;
  std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
};

}  // namespace twolink::transport
