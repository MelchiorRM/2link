#include "twolink/discovery/service.hpp"

#include <utility>

namespace twolink::discovery {

DiscoveryService::DiscoveryService(asio::io_context& io, Announcement self, ServiceConfig config,
                                   std::function<bool(const Announcement&)> is_paired,
                                   NewDeviceHandler on_new_device)
    : io_(io),
      self_(std::move(self)),
      config_(std::move(config)),
      on_new_device_(std::move(on_new_device)),
      table_(config_.table, std::move(is_paired)),
      socket_(io),
      timer_(io) {
  if (config_.broadcast) {
    config_.targets.emplace_back(asio::ip::address_v4::broadcast(), config_.listen_port);
  }
}

DiscoveryService::~DiscoveryService() {
  *alive_ = false;
  stop();
}

std::error_code DiscoveryService::start() {
  std::error_code ec;
  const asio::ip::udp::endpoint at(config_.bind_address, config_.listen_port);
  socket_.open(at.protocol(), ec);
  // Several 2Link processes on one host share the discovery port.
  if (!ec) socket_.set_option(asio::socket_base::reuse_address(true), ec);
  if (!ec) socket_.set_option(asio::socket_base::broadcast(true), ec);
  if (!ec) socket_.bind(at, ec);
  if (ec) {
    std::error_code ignored;
    socket_.close(ignored);
    return ec;
  }
  if (encode_announcement(self_, datagram_) != AnnounceError::kOk) {
    socket_.close(ec);
    return std::make_error_code(std::errc::invalid_argument);
  }
  start_receive();
  send_announcement();
  schedule_announce();
  return {};
}

void DiscoveryService::stop() {
  std::error_code ec;
  timer_.cancel();
  socket_.close(ec);
}

std::uint16_t DiscoveryService::port() const {
  std::error_code ec;
  const auto ep = socket_.local_endpoint(ec);
  return ec ? 0 : ep.port();
}

void DiscoveryService::set_tcp_port(std::uint16_t tcp_port) {
  self_.tcp_port = tcp_port;
  std::vector<std::uint8_t> d;
  if (encode_announcement(self_, d) == AnnounceError::kOk) datagram_ = std::move(d);
}

void DiscoveryService::announce_now() {
  if (socket_.is_open()) send_announcement();
}

void DiscoveryService::send_announcement() {
  // One shared buffer per round; fire and forget (UDP is lossy anyway).
  auto buf = std::make_shared<std::vector<std::uint8_t>>(datagram_);
  for (const auto& target : config_.targets) {
    socket_.async_send_to(asio::buffer(*buf), target, [buf](const std::error_code&, std::size_t) {});
  }
}

void DiscoveryService::schedule_announce() {
  timer_.expires_after(config_.interval);
  timer_.async_wait([this, alive = std::weak_ptr<bool>(alive_)](const std::error_code& ec) {
    const auto token = alive.lock();
    if (ec || !token || !*token || !socket_.is_open()) return;
    send_announcement();
    table_.expire(Clock::now());
    schedule_announce();
  });
}

void DiscoveryService::start_receive() {
  socket_.async_receive_from(
      asio::buffer(recv_buf_), sender_,
      [this, alive = std::weak_ptr<bool>(alive_)](const std::error_code& ec, std::size_t n) {
        const auto token = alive.lock();
        if (!token || !*token || !socket_.is_open()) return;
        if (!ec) on_receive(n);
        start_receive();  // errors such as ICMP port unreachable are not fatal
      });
}

void DiscoveryService::on_receive(std::size_t n) {
  Announcement a;
  if (decode_announcement(std::span(recv_buf_).first(n), a) != AnnounceError::kOk) {
    ++dropped_;
    return;
  }
  if (a.device_id == self_.device_id) return;  // our own broadcast
  const auto now = Clock::now();
  if (table_.update(a, sender_.address().to_string(), now) == DeviceTable::Update::kAdded &&
      on_new_device_) {
    if (const auto d = table_.find(a.device_id, now)) on_new_device_(*d);
  }
}

}  // namespace twolink::discovery
