#pragma once

// Command line of the 2link CLI.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace twolink::cli {

inline constexpr std::uint16_t kDefaultPort = 47821;           // spec §9 DEFAULT_TCP_PORT
inline constexpr std::uint16_t kDefaultDiscoveryPort = 47820;  // spec §9 DISCOVERY_PORT

struct Options {
  std::optional<std::filesystem::path> data_dir;  // --data-dir
  std::optional<std::string> name;                // --name
  std::uint16_t port = kDefaultPort;              // --port (TCP)
  std::uint16_t discovery_port = kDefaultDiscoveryPort;  // --discovery-port
  std::optional<std::string> host;                // chat --host
  bool no_discovery = false;                      // --no-discovery
  bool scan = false;                              // peers --scan
};

struct Command {
  enum class Kind : std::uint8_t { kHelp, kVersion, kId, kPairListen, kPairConnect, kPeers, kChat };
  Kind kind = Kind::kHelp;
  std::string target;  // pair: host[:port]; chat: peer
  Options options;
};

// Parses argv[1..]. Returns the command or an error message.
[[nodiscard]] std::variant<Command, std::string> parse_args(std::span<const std::string_view> args);

[[nodiscard]] std::string usage();

struct HostPort {
  std::string host;
  std::uint16_t port = 0;
};

// "host", "host:port", "[v6]" or "[v6]:port". nullopt if malformed.
[[nodiscard]] std::optional<HostPort> parse_host_port(std::string_view text,
                                                      std::uint16_t default_port);

}  // namespace twolink::cli
