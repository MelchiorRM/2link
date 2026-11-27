#pragma once

// One TCP connection driven by Asio, spec v0.1.3 §2.4 and §6.
//
// A Link owns the socket, a FrameParser and a connection::Connection, and
// moves bytes, frames and timer ticks between them:
//   socket -> parser -> Connection::on_frame -> bytes out -> write queue
//   timer at Connection::next_deadline()   -> Connection::on_tick
//   write queue drained                    -> Connection::on_flushed
// CONNECTING (§6.1) lives here: the TCP connect, bounded by CONNECT_TIMEOUT.
//
// Threading: every call, and every callback, happens on the io_context's
// thread. Links are reference-counted; pending Asio operations keep a Link
// alive until they complete.

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <asio.hpp>

#include "twolink/connection/connection.hpp"
#include "twolink/framing/frame_parser.hpp"

namespace twolink::transport {

using Clock = connection::Clock;
using namespace std::chrono_literals;

// §6.5.
inline constexpr Clock::duration kConnectTimeout = 5s;
// §6.6: incoming MSG frames per second before the Link stops reading (back-pressure).
inline constexpr std::size_t kMaxMessagesPerSecond = 50;

class Link : public std::enable_shared_from_this<Link> {
 public:
  using EventHandler = std::function<void(Link&, connection::Event)>;

  // Accepted socket: runs the responder side. `local` must outlive the Link.
  [[nodiscard]] static std::shared_ptr<Link> accept(asio::ip::tcp::socket socket,
                                                    const crypto::StaticKeyPair& local,
                                                    handshake::HandshakePayload local_payload,
                                                    connection::Hooks hooks, EventHandler on_event);

  // Outgoing: connects to `to`, then runs the initiator side. Connection
  // failure or timeout is reported as a kClosed event with transport_lost.
  [[nodiscard]] static std::shared_ptr<Link> connect(asio::io_context& io,
                                                     const asio::ip::tcp::endpoint& to,
                                                     const crypto::StaticKeyPair& local,
                                                     handshake::HandshakePayload local_payload,
                                                     connection::InitiatorParams params,
                                                     connection::Hooks hooks,
                                                     EventHandler on_event);

  Link(const Link&) = delete;
  Link& operator=(const Link&) = delete;
  ~Link() = default;

  // User actions, forwarded to the Connection.
  void confirm_sas();
  void reject_sas();
  [[nodiscard]] ErrorCode send_message(std::string_view text);
  // Sends CLOSE if keys exist, otherwise just closes the socket.
  void close(ErrorCode code);

  // Stops callbacks (the owner is going away) and closes the socket.
  void detach();

  // §6.6 incoming message rate; reading pauses once it is reached.
  void set_message_rate_limit(std::size_t per_second) noexcept { max_messages_ = per_second; }

  [[nodiscard]] std::uint64_t id() const noexcept { return id_; }
  // CONNECTING is reported as nullopt.
  [[nodiscard]] std::optional<connection::State> state() const noexcept;
  [[nodiscard]] bool closed() const noexcept { return closed_; }
  [[nodiscard]] const connection::Connection* connection() const noexcept {
    return conn_ ? &*conn_ : nullptr;
  }
  // Remote IP address as text: the rate-limiting source (§4.6).
  [[nodiscard]] const std::string& remote_address() const noexcept { return remote_address_; }

 private:
  Link(const asio::any_io_executor& ex, EventHandler on_event);

  void start_connect(const asio::ip::tcp::endpoint& to, const crypto::StaticKeyPair& local,
                     handshake::HandshakePayload local_payload, connection::InitiatorParams params,
                     connection::Hooks hooks);
  void remember_remote();
  void start_read();
  void on_read(const std::error_code& ec, std::size_t n);
  // Feeds buffered bytes to the parser in small slices, pausing (no reads)
  // while the message budget is used up.
  void process_pending();
  [[nodiscard]] bool message_budget_left(Clock::time_point now);
  void enqueue(connection::Bytes bytes);
  void start_write();
  // After any Connection call: send its bytes, deliver events, re-arm the
  // timer, and close the socket once the Connection is CLOSED.
  void after(connection::Bytes out);
  void arm_timer();
  void shutdown_socket();
  void report_closed_before_connect(ErrorCode code);

  std::uint64_t id_;
  asio::ip::tcp::socket socket_;
  asio::steady_timer timer_;
  EventHandler on_event_;
  std::string remote_address_;

  std::optional<connection::Connection> conn_;
  framing::FrameParser parser_;
  std::array<std::uint8_t, 16 * 1024> read_buf_{};
  std::size_t pending_begin_ = 0;  // unparsed bytes: read_buf_[pending_begin_, pending_end_)
  std::size_t pending_end_ = 0;
  asio::steady_timer read_timer_;  // resumes reading after a back-pressure pause
  std::size_t max_messages_ = kMaxMessagesPerSecond;
  Clock::time_point window_start_{};
  std::size_t window_messages_ = 0;
  std::deque<connection::Bytes> write_queue_;
  bool writing_ = false;
  bool closed_ = false;
};

}  // namespace twolink::transport
