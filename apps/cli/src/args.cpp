#include "args.hpp"

#include <charconv>
#include <vector>

namespace twolink::cli {

namespace {

std::optional<std::uint16_t> parse_port(std::string_view s) {
  unsigned value = 0;
  const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
  if (ec != std::errc{} || end != s.data() + s.size() || value == 0 || value > 65535) {
    return std::nullopt;
  }
  return static_cast<std::uint16_t>(value);
}

}  // namespace

std::string usage() {
  return R"(usage: 2link <command> [options]

commands:
  id                       show this device's identity (created on first run)
  pair --listen            open a 5-minute pairing window and wait for a device
  pair <host>[:port]       pair with a device that is listening
  peers [--scan]           list paired devices; --scan also lists devices on the LAN
  chat <peer>              chat with a paired device (name or device ID prefix)
  version                  show the version
  help                     show this help

options:
  --name <name>            device name shown to others (default: host name)
  --port <n>               TCP port (default 47821)
  --discovery-port <n>     UDP discovery port (default 47820)
  --host <host>[:port]     chat: connect to this address instead of discovering it
  --no-discovery           do not announce or listen for announcements
  --data-dir <dir>         where keys and the trust store live
)";
}

std::optional<HostPort> parse_host_port(std::string_view text, std::uint16_t default_port) {
  if (text.empty()) return std::nullopt;
  HostPort hp{std::string{}, default_port};
  std::string_view rest;
  if (text.front() == '[') {  // [IPv6]:port
    const auto close = text.find(']');
    if (close == std::string_view::npos || close == 1) return std::nullopt;
    hp.host = std::string(text.substr(1, close - 1));
    rest = text.substr(close + 1);
    if (!rest.empty() && rest.front() != ':') return std::nullopt;
  } else {
    const auto colon = text.find(':');
    if (colon != std::string_view::npos && text.find(':', colon + 1) != std::string_view::npos) {
      hp.host = std::string(text);  // bare IPv6 without a port
      return hp;
    }
    hp.host = std::string(text.substr(0, colon));
    if (colon != std::string_view::npos) rest = text.substr(colon);
    if (hp.host.empty()) return std::nullopt;
  }
  if (!rest.empty()) {
    const auto port = parse_port(rest.substr(1));
    if (!port) return std::nullopt;
    hp.port = *port;
  }
  return hp;
}

std::variant<Command, std::string> parse_args(std::span<const std::string_view> args) {
  Command cmd;
  if (args.empty()) return cmd;  // help

  const std::string_view verb = args[0];
  std::vector<std::string_view> positional;
  bool listen = false;

  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string_view a = args[i];
    auto value = [&]() -> std::optional<std::string_view> {
      if (i + 1 >= args.size()) return std::nullopt;
      return args[++i];
    };
    if (a == "--listen") {
      listen = true;
    } else if (a == "--scan") {
      cmd.options.scan = true;
    } else if (a == "--no-discovery") {
      cmd.options.no_discovery = true;
    } else if (a == "--name" || a == "--data-dir" || a == "--host" || a == "--port" ||
               a == "--discovery-port") {
      const auto v = value();
      if (!v || v->empty()) return std::string(a) + " needs a value";
      if (a == "--name") cmd.options.name = std::string(*v);
      if (a == "--data-dir") cmd.options.data_dir = std::filesystem::path(std::string(*v));
      if (a == "--host") cmd.options.host = std::string(*v);
      if (a == "--port" || a == "--discovery-port") {
        const auto p = parse_port(*v);
        if (!p) return "invalid port: " + std::string(*v);
        (a == "--port" ? cmd.options.port : cmd.options.discovery_port) = *p;
      }
    } else if (a.starts_with("--")) {
      return "unknown option: " + std::string(a);
    } else {
      positional.push_back(a);
    }
  }

  auto expect_positional = [&](std::size_t n) -> std::optional<std::string> {
    if (positional.size() != n) return "wrong number of arguments for '" + std::string(verb) + "'";
    return std::nullopt;
  };

  if (verb == "help" || verb == "--help" || verb == "-h") {
    cmd.kind = Command::Kind::kHelp;
  } else if (verb == "version" || verb == "--version") {
    cmd.kind = Command::Kind::kVersion;
  } else if (verb == "id") {
    if (auto e = expect_positional(0)) return *e;
    cmd.kind = Command::Kind::kId;
  } else if (verb == "pair") {
    if (listen) {
      if (auto e = expect_positional(0)) return "pair --listen takes no host";
      cmd.kind = Command::Kind::kPairListen;
    } else {
      if (auto e = expect_positional(1)) return "usage: 2link pair --listen | 2link pair <host>[:port]";
      if (!parse_host_port(positional[0], cmd.options.port)) {
        return "invalid address: " + std::string(positional[0]);
      }
      cmd.kind = Command::Kind::kPairConnect;
      cmd.target = std::string(positional[0]);
    }
  } else if (verb == "peers") {
    if (auto e = expect_positional(0)) return *e;
    cmd.kind = Command::Kind::kPeers;
  } else if (verb == "chat") {
    if (auto e = expect_positional(1)) return "usage: 2link chat <peer> [--host <host>[:port]]";
    if (cmd.options.host && !parse_host_port(*cmd.options.host, kDefaultPort)) {
      return "invalid address: " + *cmd.options.host;
    }
    cmd.kind = Command::Kind::kChat;
    cmd.target = std::string(positional[0]);
  } else {
    return "unknown command: " + std::string(verb);
  }
  if (listen && cmd.kind != Command::Kind::kPairListen) return "--listen only applies to 'pair'";
  if (cmd.options.scan && cmd.kind != Command::Kind::kPeers) return "--scan only applies to 'peers'";
  if (cmd.options.host && cmd.kind != Command::Kind::kChat) return "--host only applies to 'chat'";
  return cmd;
}

}  // namespace twolink::cli
