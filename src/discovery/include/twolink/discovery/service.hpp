#pragma once

// UDP discovery on Asio, spec v0.1.3 §8.1: announce this device every
// kAnnounceInterval and record valid announcements from others in a
// DeviceTable. Never connects to anything and never changes trust.
//
// Threading: everything runs on the io_context's thread.

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <system_error>
#include <vector>

#include <asio.hpp>

#include "twolink/discovery/announcement.hpp"
#include "twolink/discovery/device_table.hpp"

namespace twolink::discovery {

struct ServiceConfig {
  asio::ip::address bind_address = asio::ip::address_v4::any();
  std::uint16_t listen_port = kDiscoveryPort;
  // Announce to the IPv4 broadcast address on listen_port (§8.1)...
  bool broadcast = true;
  // ...and to these endpoints (tests, unicast setups).
  std::vector<asio::ip::udp::endpoint> targets;
  Clock::duration interval = kAnnounceInterval;
  DeviceTable::Config table;
};

class DiscoveryService {
 public:
  // Called for a device seen for the first time (or again after expiring).
  using NewDeviceHandler = std::function<void(const DiscoveredDevice&)>;

  // is_paired protects paired devices from eviction (DeviceTable).
  DiscoveryService(asio::io_context& io, Announcement self, ServiceConfig config,
                   std::function<bool(const Announcement&)> is_paired = {},
                   NewDeviceHandler on_new_device = {});
  ~DiscoveryService();

  DiscoveryService(const DiscoveryService&) = delete;
  DiscoveryService& operator=(const DiscoveryService&) = delete;

  // Binds the socket, starts listening and announcing.
  [[nodiscard]] std::error_code start();
  void stop();

  // Announces now (e.g. after the TCP port changed).
  void announce_now();
  void set_tcp_port(std::uint16_t port);
  // Also announce to `target` (tests and unicast setups).
  void add_target(const asio::ip::udp::endpoint& target) { config_.targets.push_back(target); }

  [[nodiscard]] const DeviceTable& table() const noexcept { return table_; }
  [[nodiscard]] std::uint16_t port() const;
  // Datagrams dropped as malformed, for diagnostics.
  [[nodiscard]] std::uint64_t dropped() const noexcept { return dropped_; }

 private:
  void start_receive();
  void on_receive(std::size_t n);
  void schedule_announce();
  void send_announcement();

  asio::io_context& io_;
  Announcement self_;
  ServiceConfig config_;
  NewDeviceHandler on_new_device_;
  DeviceTable table_;
  asio::ip::udp::socket socket_;
  asio::steady_timer timer_;
  std::array<std::uint8_t, kMaxDatagramSize + 1> recv_buf_{};  // +1 detects oversize
  asio::ip::udp::endpoint sender_;
  std::vector<std::uint8_t> datagram_;
  std::uint64_t dropped_ = 0;
  std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
};

}  // namespace twolink::discovery
