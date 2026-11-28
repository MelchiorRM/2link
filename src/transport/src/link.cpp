#include "twolink/transport/link.hpp"

#include <algorithm>
#include <atomic>
#include <utility>

namespace twolink::transport {

namespace {
std::atomic<std::uint64_t> g_next_id{1};
}  // namespace

Link::Link(const asio::any_io_executor& ex, EventHandler on_event)
    : id_(g_next_id.fetch_add(1)),
      socket_(ex),
      timer_(ex),
      on_event_(std::move(on_event)),
      read_timer_(ex) {}

std::shared_ptr<Link> Link::accept(asio::ip::tcp::socket socket, const crypto::StaticKeyPair& local,
                                   handshake::HandshakePayload local_payload,
                                   connection::Hooks hooks, EventHandler on_event) {
  std::shared_ptr<Link> link(new Link(socket.get_executor(), std::move(on_event)));
  link->socket_ = std::move(socket);
  link->remember_remote();
  std::error_code ec;
  link->socket_.set_option(asio::ip::tcp::no_delay(true), ec);

  link->conn_ = connection::Connection::accept(local, std::move(local_payload), std::move(hooks),
                                               Clock::now());
  if (!link->conn_) {
    link->shutdown_socket();
    return link;
  }
  link->arm_timer();  // HANDSHAKE_TIMEOUT
  link->start_read();
  return link;
}

std::shared_ptr<Link> Link::connect(asio::io_context& io, const asio::ip::tcp::endpoint& to,
                                    const crypto::StaticKeyPair& local,
                                    handshake::HandshakePayload local_payload,
                                    connection::InitiatorParams params, connection::Hooks hooks,
                                    EventHandler on_event) {
  std::shared_ptr<Link> link(new Link(io.get_executor(), std::move(on_event)));
  link->start_connect(to, local, std::move(local_payload), params, std::move(hooks));
  return link;
}

void Link::start_connect(const asio::ip::tcp::endpoint& to, const crypto::StaticKeyPair& local,
                         handshake::HandshakePayload local_payload,
                         connection::InitiatorParams params, connection::Hooks hooks) {
  auto timed_out = std::make_shared<bool>(false);
  timer_.expires_after(kConnectTimeout);
  timer_.async_wait([self = shared_from_this(), timed_out](const std::error_code& ec) {
    if (ec || self->conn_ || self->closed_) return;
    *timed_out = true;
    std::error_code ignored;
    self->socket_.close(ignored);  // aborts async_connect
  });

  socket_.async_connect(
      to, [self = shared_from_this(), timed_out, &local, payload = std::move(local_payload), params,
           hooks = std::move(hooks)](const std::error_code& ec) mutable {
        if (self->closed_) return;
        if (ec) {
          self->report_closed_before_connect(*timed_out ? ErrorCode::kTimeout : ErrorCode::kNoError);
          return;
        }
        self->timer_.cancel();
        self->remember_remote();
        std::error_code ignored;
        self->socket_.set_option(asio::ip::tcp::no_delay(true), ignored);

        connection::Bytes out;
        self->conn_ = connection::Connection::initiate(local, std::move(payload), params,
                                                       std::move(hooks), Clock::now(), out);
        if (!self->conn_) {
          self->report_closed_before_connect(ErrorCode::kInternalError);
          return;
        }
        self->after(std::move(out));
        if (!self->closed_) self->start_read();
      });
}

void Link::remember_remote() {
  std::error_code ec;
  const auto ep = socket_.remote_endpoint(ec);
  if (!ec) remote_address_ = ep.address().to_string();
}

std::optional<connection::State> Link::state() const noexcept {
  if (conn_) return conn_->state();
  if (closed_) return connection::State::kClosed;
  return std::nullopt;
}

// --- reading --------------------------------------------------------------------

void Link::start_read() {
  socket_.async_read_some(asio::buffer(read_buf_),
                          [self = shared_from_this()](const std::error_code& ec, std::size_t n) {
                            self->on_read(ec, n);
                          });
}

void Link::on_read(const std::error_code& ec, std::size_t n) {
  if (closed_ || !conn_) return;
  if (ec) {
    conn_->on_transport_lost();
    after({});
    return;
  }
  pending_begin_ = 0;
  pending_end_ = n;
  process_pending();
}

bool Link::message_budget_left(Clock::time_point now) {
  if (now - window_start_ >= 1s) {
    window_start_ = now;
    window_messages_ = 0;
  }
  return window_messages_ < max_messages_;
}

void Link::process_pending() {
  constexpr std::size_t kSlice = 512;  // bounds how far one pass can overshoot the budget
  while (pending_begin_ < pending_end_) {
    if (closed_ || !conn_) return;
    const auto now = Clock::now();
    if (!message_budget_left(now)) {
      // Back-pressure (§6.6): stop reading until the next window.
      read_timer_.expires_at(window_start_ + 1s);
      read_timer_.async_wait([self = shared_from_this()](const std::error_code& e) {
        if (!e && !self->closed_) self->process_pending();
      });
      return;
    }
    const std::size_t n = std::min(kSlice, pending_end_ - pending_begin_);
    connection::Bytes out;
    const framing::FrameError err = parser_.feed(
        std::span(read_buf_).subspan(pending_begin_, n), [&](const framing::FrameView& frame) {
          if (frame.header.type == framing::FrameType::kMsg) ++window_messages_;
          conn_->on_frame(frame.header, frame.payload, now, out);
        });
    pending_begin_ += n;
    if (err != framing::FrameError::kOk) {
      // Malformed input is fatal (§1); with keys the Connection sends CLOSE.
      conn_->close(framing::to_error_code(err), now, out);
    }
    after(std::move(out));
  }
  if (!closed_) start_read();
}

// --- writing --------------------------------------------------------------------

void Link::enqueue(connection::Bytes bytes) {
  if (bytes.empty() || closed_) return;
  write_queue_.push_back(std::move(bytes));
  start_write();
}

void Link::start_write() {
  if (writing_ || write_queue_.empty() || closed_) return;
  writing_ = true;
  asio::async_write(socket_, asio::buffer(write_queue_.front()),
                    [self = shared_from_this()](const std::error_code& ec, std::size_t) {
                      self->writing_ = false;
                      if (self->closed_ || !self->conn_) return;
                      if (ec) {
                        self->conn_->on_transport_lost();
                        self->after({});
                        return;
                      }
                      self->write_queue_.pop_front();
                      if (self->write_queue_.empty()) {
                        self->conn_->on_flushed(Clock::now());
                        self->after({});
                      } else {
                        self->start_write();
                      }
                    });
}

// --- glue -------------------------------------------------------------------------

void Link::after(connection::Bytes out) {
  if (!conn_) return;
  enqueue(std::move(out));
  for (connection::Event& e : conn_->take_events()) {
    if (on_event_) on_event_(*this, std::move(e));
  }
  if (closed_) return;  // a handler may have closed or detached us
  if (conn_->state() == connection::State::kClosed) {
    shutdown_socket();
  } else {
    arm_timer();
  }
}

void Link::arm_timer() {
  const auto deadline = conn_->next_deadline();
  if (!deadline) {
    timer_.cancel();
    return;
  }
  timer_.expires_at(*deadline);
  timer_.async_wait([self = shared_from_this()](const std::error_code& ec) {
    if (ec || self->closed_ || !self->conn_) return;
    connection::Bytes out;
    self->conn_->on_tick(Clock::now(), out);
    self->after(std::move(out));
  });
}

void Link::shutdown_socket() {
  if (closed_) return;
  closed_ = true;
  timer_.cancel();
  read_timer_.cancel();
  std::error_code ec;
  socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
  socket_.close(ec);
}

void Link::report_closed_before_connect(ErrorCode code) {
  shutdown_socket();
  connection::Event e(connection::Event::Kind::kClosed);
  e.code = code;
  e.transport_lost = true;
  if (on_event_) on_event_(*this, std::move(e));
}

// --- user actions -------------------------------------------------------------------

void Link::confirm_sas() {
  if (closed_ || !conn_) return;
  connection::Bytes out;
  conn_->confirm_sas(Clock::now(), out);
  after(std::move(out));
}

void Link::reject_sas() {
  if (closed_ || !conn_) return;
  connection::Bytes out;
  conn_->reject_sas(Clock::now(), out);
  after(std::move(out));
}

ErrorCode Link::send_message(std::string_view text) {
  if (closed_ || !conn_) return ErrorCode::kInternalError;
  connection::Bytes out;
  const ErrorCode e = conn_->send_message(text, Clock::now(), out);
  after(std::move(out));
  return e;
}

void Link::close(ErrorCode code) {
  if (closed_) return;
  if (!conn_) {  // still connecting
    report_closed_before_connect(code);
    return;
  }
  connection::Bytes out;
  conn_->close(code, Clock::now(), out);
  after(std::move(out));
}

void Link::detach() {
  on_event_ = nullptr;
  shutdown_socket();
}

}  // namespace twolink::transport
