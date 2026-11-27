#include "app.hpp"

#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <asio.hpp>

#include "peers.hpp"
#include "twolink/core/version.hpp"
#include "twolink/crypto/keys.hpp"
#include "twolink/discovery/service.hpp"
#include "twolink/handshake/payload.hpp"
#include "twolink/identity/identity.hpp"
#include "twolink/identity/keystore.hpp"
#include "twolink/identity/trust_store.hpp"
#include "twolink/transport/node.hpp"

namespace twolink::cli {

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using identity::DeviceId;

std::string printable(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    const auto b = static_cast<unsigned char>(s[i]);
    if (b < 0x20 || b == 0x7F) {
      out += '?';
    } else if (b == 0xC2 && i + 1 < s.size() && static_cast<unsigned char>(s[i + 1]) >= 0x80 &&
               static_cast<unsigned char>(s[i + 1]) <= 0x9F) {
      out += '?';  // C1 control (U+0080..U+009F), e.g. CSI
      ++i;
    } else {
      out += static_cast<char>(b);
    }
  }
  return out;
}

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailed = 1;

// --- local state: identity, trust store, name ------------------------------------

struct Local {
  fs::path data_dir;
  std::unique_ptr<identity::FileKeystore> keystore;
  std::optional<identity::Identity> id;
  std::optional<identity::TrustStore> trust;
  std::string name;
  bool created = false;
};

std::unique_ptr<Local> open_local(const Options& opts, std::ostream& err) {
  if (!crypto::initialize()) {
    err << "error: crypto library failed to initialise\n";
    return nullptr;
  }
  auto local = std::make_unique<Local>();
  if (opts.data_dir) {
    local->data_dir = *opts.data_dir;
  } else if (auto d = identity::default_data_dir()) {
    local->data_dir = *d;
  } else {
    err << "error: no data directory; set HOME or use --data-dir\n";
    return nullptr;
  }
  local->keystore = std::make_unique<identity::FileKeystore>(local->data_dir / "keys");

  const auto ks = identity::load_or_create_identity(*local->keystore, local->id, &local->created);
  if (ks != identity::KeystoreStatus::kOk) {
    err << "error: cannot load the device key (" << identity::to_string(ks) << ") in "
        << (local->data_dir / "keys").string() << "\n"
        << "The key is never replaced automatically: a new key would make this a new device\n"
        << "to every paired peer.\n";
    return nullptr;
  }
  const auto ts = identity::TrustStore::open(*local->keystore, local->data_dir / "trust-store.bin",
                                             local->trust);
  if (ts != identity::TrustStoreStatus::kOk) {
    err << "error: cannot open the trust store (" << identity::to_string(ts) << ")\n";
    return nullptr;
  }

  if (opts.name) {
    if (!handshake::is_valid_device_name(*opts.name)) {
      err << "error: --name must be 1 to 64 bytes of UTF-8\n";
      return nullptr;
    }
    local->name = *opts.name;
  } else {
    local->name = sanitize_device_name(asio::ip::host_name());
  }
  return local;
}

std::string label(const DeviceId& id) { return identity::display_form(id); }

std::string reason_text(const transport::ClosedInfo& c) {
  if (!c.transport_lost && c.code == ErrorCode::kNoError) {
    return c.by_peer ? "the other device closed the connection" : "closed";
  }
  if (c.transport_lost && c.code == ErrorCode::kNoError) return "connection lost";
  if (c.transport_lost && c.code == ErrorCode::kTimeout) return "connection timed out";
  std::string text(to_string(c.code));
  if (c.by_peer) text += " (from the other device)";
  if (!c.reason.empty()) text += ": " + printable(c.reason);
  return text;
}

// --- standard input on a thread, delivered on the io_context ------------------------

void read_stdin(asio::io_context& io, std::function<void(std::optional<std::string>)> on_line) {
  std::thread([&io, on_line = std::move(on_line)] {
    std::string line;
    while (std::getline(std::cin, line)) {
      if (!line.empty() && line.back() == '\r') line.pop_back();
      asio::post(io, [on_line, line] { on_line(line); });
    }
    asio::post(io, [on_line] { on_line(std::nullopt); });
  }).detach();  // blocked in getline until exit; the process ends it
}

// The event loop lives for the whole process: the stdin thread may still post
// to it while a command is shutting down.
asio::io_context& process_io() {
  static auto* io = new asio::io_context;  // intentionally never destroyed
  return *io;
}

// --- a session: node + optional discovery ---------------------------------------------

class Session {
 public:
  Session(Local& local, const Options& opts, std::ostream& out, std::ostream& err)
      : local_(local), opts_(opts), out_(out), err_(err), io_(process_io()) {
    transport::NodeObserver obs;
    obs.on_sas = [this](const transport::SasPrompt& p) { on_sas(p); };
    obs.on_established = [this](const transport::PeerInfo& p) {
      if (on_established) on_established(p);
    };
    obs.on_message = [this](const DeviceId& from, const std::string& text) {
      out_ << "[" << peer_name(from) << "] " << printable(text) << std::endl;
    };
    obs.on_closed = [this](const transport::ClosedInfo& c) {
      if (pending_sas_ && *pending_sas_ == c.link) {
        pending_sas_.reset();
        out_ << "(the pairing attempt ended)" << std::endl;
      }
      if (on_closed) on_closed(c);
    };
    node_ = std::make_unique<transport::Node>(io_, local.id->key, *local.trust, local.name,
                                              std::move(obs));
  }

  ~Session() {
    discovery_.reset();
    node_.reset();
  }

  bool listen() {
    const auto ec = node_->listen({asio::ip::address_v4::any(), opts_.port});
    if (ec) {
      err_ << "error: cannot listen on TCP port " << opts_.port << ": " << ec.message() << "\n";
      return false;
    }
    return true;
  }

  void start_discovery(std::uint16_t tcp_port) {
    if (opts_.no_discovery) return;
    discovery::ServiceConfig cfg;
    cfg.listen_port = opts_.discovery_port;
    discovery_ = std::make_unique<discovery::DiscoveryService>(
        io_, discovery::make_announcement(local_.name, local_.id->key.public_key(), tcp_port), cfg,
        [this](const discovery::Announcement& a) { return local_.trust->find_by_key(a.static_key) != nullptr; });
    if (const auto ec = discovery_->start()) {
      err_ << "warning: discovery unavailable on UDP port " << opts_.discovery_port << ": "
           << ec.message() << "\n";
      discovery_.reset();
    }
  }

  // Lines typed by the user. Answers a pending SAS question first.
  void on_input(std::optional<std::string> line) {
    if (pending_sas_) {
      const transport::LinkId link = *pending_sas_;
      pending_sas_.reset();
      const bool yes = line && (*line == "y" || *line == "Y" || *line == "yes");
      if (yes) {
        out_ << "Confirmed. Waiting for the other device..." << std::endl;
        node_->confirm_sas(link);
      } else {
        out_ << "Rejected." << std::endl;
        node_->reject_sas(link);
      }
      return;
    }
    if (on_line) on_line(std::move(line));
  }

  std::optional<asio::ip::tcp::endpoint> resolve(const HostPort& hp) {
    asio::ip::tcp::resolver resolver(io_);
    std::error_code ec;
    const auto results = resolver.resolve(hp.host, std::to_string(hp.port), ec);
    if (ec || results.empty()) {
      err_ << "error: cannot resolve " << hp.host << ": " << ec.message() << "\n";
      return std::nullopt;
    }
    return results.begin()->endpoint();
  }

  std::string peer_name(const DeviceId& id) const {
    if (const auto* r = local_.trust->find(id)) return printable(r->name);
    return label(id);
  }

  int run() {
    io_.restart();
    auto guard = asio::make_work_guard(io_);
    io_.run();
    return exit_code_;
  }

  void finish(int code, std::chrono::milliseconds linger = 0ms) {
    exit_code_ = code;
    if (linger == 0ms) {
      io_.stop();
      return;
    }
    auto timer = std::make_shared<asio::steady_timer>(io_, linger);  // let CLOSE go out
    timer->async_wait([this, timer](const std::error_code&) { io_.stop(); });
  }

  asio::io_context& io() { return io_; }
  transport::Node& node() { return *node_; }
  discovery::DiscoveryService* discovery() { return discovery_.get(); }
  Local& local() { return local_; }

  std::function<void(const transport::PeerInfo&)> on_established;
  std::function<void(const transport::ClosedInfo&)> on_closed;
  std::function<void(std::optional<std::string>)> on_line;

 private:
  void on_sas(const transport::SasPrompt& p) {
    out_ << "\nPairing with \"" << printable(p.name) << "\" (" << label(p.device_id) << ")\n"
         << "\n    Verification code:  " << p.sas << "\n\n";
    if (!p.same_name_as.empty()) {
      out_ << "WARNING: you already trust a different device named \"" << printable(p.name)
           << "\" (" << label(p.same_name_as.front()) << ").\n"
           << "This may be a new installation of it, or an impostor. Confirming replaces it.\n\n";
    }
    out_ << "Compare it with the code on the other device.\n"
         << "Do both screens show the same code? [y/N] " << std::flush;
    pending_sas_ = p.link;
  }

  Local& local_;
  const Options& opts_;
  std::ostream& out_;
  std::ostream& err_;
  asio::io_context& io_;
  std::unique_ptr<transport::Node> node_;
  std::unique_ptr<discovery::DiscoveryService> discovery_;
  std::optional<transport::LinkId> pending_sas_;
  int exit_code_ = kExitFailed;
};

// --- commands -------------------------------------------------------------------------

int cmd_id(const Options& opts, std::ostream& out, std::ostream& err) {
  auto local = open_local(opts, err);
  if (!local) return kExitFailed;
  if (local->created) out << "Created a new device identity.\n";
  out << "Device name: " << local->name << "\n"
      << "Device ID:   " << label(local->id->device_id) << "\n"
      << "Full ID:     " << identity::to_hex(local->id->device_id) << "\n"
      << "Data:        " << local->data_dir.string() << "\n"
      << "Paired:      " << local->trust->peers().size() << " device(s)\n";
  return kExitOk;
}

int cmd_pair_listen(const Options& opts, std::ostream& out, std::ostream& err) {
  auto local = open_local(opts, err);
  if (!local) return kExitFailed;
  Session s(*local, opts, out, err);
  if (!s.listen()) return kExitFailed;
  s.start_discovery(s.node().port());
  s.node().open_pairing_window();
  out << "Pairing window open for 5 minutes on TCP port " << s.node().port() << ".\n"
      << "This device: \"" << local->name << "\" (" << label(local->id->device_id) << ")\n"
      << "On the other device run:  2link pair <this computer's address>\n"
      << "Press Enter on an empty line to cancel.\n"
      << std::flush;

  asio::steady_timer window(s.io(), connection::kPairWindow);
  window.async_wait([&](const std::error_code& ec) {
    if (ec) return;
    out << "The pairing window closed." << std::endl;
    s.finish(kExitFailed);
  });
  s.on_established = [&](const transport::PeerInfo& p) {
    if (!p.paired) return;
    out << "Paired with \"" << printable(p.name) << "\" (" << label(p.device_id) << ")." << std::endl;
    s.finish(kExitOk, 300ms);
  };
  s.on_closed = [&](const transport::ClosedInfo& c) {
    if (!c.device_id) return;  // refused before the handshake finished: nothing to tell
    out << "Pairing attempt failed: " << reason_text(c) << std::endl;
  };
  s.on_line = [&](std::optional<std::string> line) {
    if (line && !line->empty()) {
      out << "(no pairing request yet; press Enter on an empty line to cancel)" << std::endl;
      return;
    }
    out << "Cancelled." << std::endl;
    s.finish(kExitFailed);
  };
  read_stdin(s.io(), [&](std::optional<std::string> line) { s.on_input(std::move(line)); });
  return s.run();
}

int cmd_pair_connect(const std::string& target, const Options& opts, std::ostream& out,
                     std::ostream& err) {
  auto local = open_local(opts, err);
  if (!local) return kExitFailed;
  const auto hp = parse_host_port(target, kDefaultPort);
  Session s(*local, opts, out, err);
  const auto ep = s.resolve(*hp);
  if (!ep) return kExitFailed;

  out << "Connecting to " << hp->host << ":" << ep->port() << "..." << std::endl;
  s.on_established = [&](const transport::PeerInfo& p) {
    if (!p.paired) return;
    out << "Paired with \"" << printable(p.name) << "\" (" << label(p.device_id) << ")." << std::endl;
    s.finish(kExitOk, 300ms);
  };
  s.on_closed = [&](const transport::ClosedInfo& c) {
    out << "Pairing failed: " << reason_text(c) << std::endl;
    if (!c.device_id) {
      out << "(Is \"2link pair --listen\" running on the other device?)" << std::endl;
    }
    s.finish(kExitFailed);
  };
  s.on_line = [](std::optional<std::string>) {};
  s.node().pair(*ep);
  read_stdin(s.io(), [&](std::optional<std::string> line) { s.on_input(std::move(line)); });
  return s.run();
}

int cmd_peers(const Options& opts, std::ostream& out, std::ostream& err) {
  auto local = open_local(opts, err);
  if (!local) return kExitFailed;
  const auto& peers = local->trust->peers();
  if (peers.empty()) {
    out << "No paired devices. Pair with: 2link pair --listen / 2link pair <host>\n";
  } else {
    out << "Paired devices:\n";
    for (const auto& r : peers) {
      out << "  " << label(r.device_id) << "  " << printable(r.name) << "  (paired "
          << format_utc(r.first_paired_at) << ")\n";
    }
  }
  if (!opts.scan) return kExitOk;

  if (opts.no_discovery) {
    err << "error: --scan needs discovery\n";
    return kExitFailed;
  }
  Session s(*local, opts, out, err);
  s.start_discovery(opts.port);
  if (!s.discovery()) return kExitFailed;
  out << "Scanning the LAN for " << 6 << " seconds..." << std::endl;
  asio::steady_timer t(s.io(), 6s);
  t.async_wait([&](const std::error_code&) { s.finish(kExitOk); });
  s.run();

  const auto found = s.discovery()->table().devices(discovery::Clock::now());
  if (found.empty()) {
    out << "No devices found.\n";
    return kExitOk;
  }
  out << "Devices on the LAN:\n";
  for (const auto& d : found) {
    const auto status = discovery::classify(d.announcement, *local->trust);
    const char* tag = status == discovery::DeviceStatus::kPaired ? "paired"
                      : status == discovery::DeviceStatus::kUnverified
                          ? "unverified"
                          : "unverified - WARNING: uses the name of a paired device";
    out << "  " << label(d.announcement.device_id) << "  " << printable(d.announcement.device_name)
        << "  " << d.address << ":" << d.announcement.tcp_port << "  [" << tag << "]\n";
  }
  return kExitOk;
}

int cmd_chat(const std::string& query, const Options& opts, std::ostream& out, std::ostream& err) {
  auto local = open_local(opts, err);
  if (!local) return kExitFailed;
  const PeerMatch m = resolve_peer(*local->trust, query);
  if (m.result != PeerMatch::Result::kFound) {
    err << (m.result == PeerMatch::Result::kNotFound ? "error: no paired device matches \""
                                                     : "error: several paired devices match \"")
        << printable(query) << "\"; see 2link peers\n";
    return kExitFailed;
  }
  const DeviceId peer = m.matches.front()->device_id;
  const std::string name = printable(m.matches.front()->name);

  Session s(*local, opts, out, err);
  const bool listening = s.listen();  // the peer may connect to us instead
  s.start_discovery(listening ? s.node().port() : opts.port);
  std::optional<asio::ip::tcp::endpoint> fixed;
  if (opts.host) {
    fixed = s.resolve(*parse_host_port(*opts.host, kDefaultPort));
    if (!fixed) return kExitFailed;
  } else if (!s.discovery() && !listening) {
    err << "error: neither listening nor discovering; use --host\n";
    return kExitFailed;
  }

  bool connected = false;
  bool quitting = false;
  std::optional<transport::LinkId> attempt;
  out << "Looking for \"" << name << "\" (" << label(peer) << ")... type /quit to leave." << std::endl;

  asio::steady_timer retry(s.io());
  std::function<void()> try_connect = [&] {
    if (!s.node().connected(peer) && !attempt) {
      std::optional<asio::ip::tcp::endpoint> to = fixed;
      if (!to && s.discovery()) {
        if (const auto d = s.discovery()->table().find(peer, discovery::Clock::now())) {
          std::error_code ec;
          const auto addr = asio::ip::make_address(d->address, ec);
          if (!ec) to = asio::ip::tcp::endpoint(addr, d->announcement.tcp_port);
        }
      }
      if (to) attempt = s.node().reconnect(peer, *to);  // pins the trusted key (§4.8)
    }
    retry.expires_after(2s);
    retry.async_wait([&](const std::error_code& ec) {
      if (!ec && !quitting) try_connect();
    });
  };

  s.on_established = [&](const transport::PeerInfo& p) {
    if (p.device_id != peer || p.role != handshake::ConnectionRole::kPrimary) return;
    attempt.reset();
    if (!connected) out << "Connected to \"" << name << "\"." << std::endl;
    connected = true;
  };
  s.on_closed = [&](const transport::ClosedInfo& c) {
    if (attempt && *attempt == c.link) attempt.reset();
    if (connected && !quitting && !s.node().connected(peer)) {
      connected = false;
      out << "Disconnected from \"" << name << "\" (" << reason_text(c) << "). Reconnecting..."
          << std::endl;
    }
  };
  s.on_line = [&](std::optional<std::string> line) {
    if (!line || *line == "/quit") {
      quitting = true;
      retry.cancel();
      s.node().disconnect(peer);
      s.finish(kExitOk, 300ms);
      return;
    }
    if (line->empty()) return;
    if (!s.node().connected(peer)) {
      out << "(not connected; message not sent)" << std::endl;
      return;
    }
    const ErrorCode e = s.node().send_message(peer, *line);
    if (e != ErrorCode::kNoError) out << "(not sent: " << to_string(e) << ")" << std::endl;
  };
  try_connect();
  read_stdin(s.io(), [&](std::optional<std::string> line) { s.on_input(std::move(line)); });
  return s.run();
}

}  // namespace

int run(const Command& command, std::ostream& out, std::ostream& err) {
  switch (command.kind) {
    case Command::Kind::kHelp: out << usage(); return kExitOk;
    case Command::Kind::kVersion:
      out << "2link " << library_version() << " (protocol v" << static_cast<int>(kProtocolVersion)
          << ")\n";
      return kExitOk;
    case Command::Kind::kId: return cmd_id(command.options, out, err);
    case Command::Kind::kPairListen: return cmd_pair_listen(command.options, out, err);
    case Command::Kind::kPairConnect:
      return cmd_pair_connect(command.target, command.options, out, err);
    case Command::Kind::kPeers: return cmd_peers(command.options, out, err);
    case Command::Kind::kChat: return cmd_chat(command.target, command.options, out, err);
  }
  return kExitFailed;
}

}  // namespace twolink::cli
