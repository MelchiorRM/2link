#pragma once

// A TCP man-in-the-middle for integration tests: forwards every connection it
// accepts to `target`, records all bytes per direction, and lets a test
// rewrite chunks in flight.

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <asio.hpp>

namespace twolink::test {

class TcpProxy {
 public:
  using Bytes = std::vector<std::uint8_t>;
  // Called for every chunk before it is forwarded; may modify or clear it.
  // conn is the 0-based index of the proxied connection.
  using Tamper = std::function<void(Bytes& chunk, bool client_to_server, std::size_t conn)>;

  TcpProxy(asio::io_context& io, asio::ip::tcp::endpoint target)
      : io_(io), target_(target), acceptor_(io, {asio::ip::address_v4::loopback(), 0}) {
    accept();
  }
  ~TcpProxy() { stop(); }

  [[nodiscard]] asio::ip::tcp::endpoint endpoint() const {
    return {asio::ip::address_v4::loopback(), acceptor_.local_endpoint().port()};
  }

  void stop() {
    std::error_code ec;
    acceptor_.close(ec);
    for (auto& c : conns_) c->close();
  }

  // Everything that went through, per direction and connection.
  [[nodiscard]] Bytes sent(bool client_to_server, std::size_t conn) const {
    if (conn >= conns_.size()) return {};
    return client_to_server ? conns_[conn]->c2s : conns_[conn]->s2c;
  }
  [[nodiscard]] Bytes all_bytes() const {
    Bytes all;
    for (const auto& c : conns_) {
      all.insert(all.end(), c->c2s.begin(), c->c2s.end());
      all.insert(all.end(), c->s2c.begin(), c->s2c.end());
    }
    return all;
  }
  [[nodiscard]] std::size_t connections() const noexcept { return conns_.size(); }

  // Writes raw bytes into connection `conn`, towards the server or the client.
  void inject(std::size_t conn, bool to_server, Bytes bytes) {
    auto c = conns_.at(conn);
    auto buf = std::make_shared<Bytes>(std::move(bytes));
    asio::async_write(to_server ? c->server : c->client, asio::buffer(*buf),
                      [buf, c](const std::error_code&, std::size_t) {});
  }

  Tamper tamper;

 private:
  struct Conn : std::enable_shared_from_this<Conn> {
    explicit Conn(asio::io_context& io) : client(io), server(io) {}
    asio::ip::tcp::socket client;
    asio::ip::tcp::socket server;
    Bytes c2s, s2c;
    std::array<std::uint8_t, 8192> buf_c{}, buf_s{};
    void close() {
      std::error_code ec;
      client.close(ec);
      server.close(ec);
    }
  };

  void accept() {
    auto c = std::make_shared<Conn>(io_);
    acceptor_.async_accept(c->client, [this, c](const std::error_code& ec) {
      if (ec) return;
      const std::size_t index = conns_.size();
      conns_.push_back(c);
      c->server.async_connect(target_, [this, c, index](const std::error_code& e) {
        if (e) {
          c->close();
          return;
        }
        pump(c, true, index);
        pump(c, false, index);
      });
      accept();
    });
  }

  void pump(const std::shared_ptr<Conn>& c, bool c2s, std::size_t index) {
    auto& from = c2s ? c->client : c->server;
    auto& buf = c2s ? c->buf_c : c->buf_s;
    from.async_read_some(asio::buffer(buf), [this, c, c2s, index](const std::error_code& ec,
                                                                  std::size_t n) {
      if (ec) {
        c->close();
        return;
      }
      auto chunk = std::make_shared<Bytes>((c2s ? c->buf_c : c->buf_s).begin(),
                                           (c2s ? c->buf_c : c->buf_s).begin() +
                                               static_cast<std::ptrdiff_t>(n));
      auto& log = c2s ? c->c2s : c->s2c;
      log.insert(log.end(), chunk->begin(), chunk->end());
      if (tamper) tamper(*chunk, c2s, index);
      auto& to = c2s ? c->server : c->client;
      asio::async_write(to, asio::buffer(*chunk),
                        [this, c, c2s, index, chunk](const std::error_code& e, std::size_t) {
                          if (e) {
                            c->close();
                            return;
                          }
                          pump(c, c2s, index);
                        });
    });
  }

  asio::io_context& io_;
  asio::ip::tcp::endpoint target_;
  asio::ip::tcp::acceptor acceptor_;
  std::vector<std::shared_ptr<Conn>> conns_;
};

}  // namespace twolink::test
