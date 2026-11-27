// CLI argument parsing, peer lookup and output sanitizing.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "src/app.hpp"
#include "src/args.hpp"
#include "src/peers.hpp"
#include "twolink/crypto/keys.hpp"
#include "twolink/identity/keystore.hpp"

namespace {

namespace fs = std::filesystem;
using namespace twolink::cli;
using Kind = Command::Kind;

std::variant<Command, std::string> parse(std::vector<std::string_view> args) {
  return parse_args(args);
}

Command ok(std::vector<std::string_view> args) {
  auto r = parse(std::move(args));
  EXPECT_TRUE(std::holds_alternative<Command>(r)) << std::get<std::string>(r);
  return std::holds_alternative<Command>(r) ? std::get<Command>(r) : Command{};
}

bool fails(std::vector<std::string_view> args) {
  return std::holds_alternative<std::string>(parse(std::move(args)));
}

TEST(CliArgs, Commands) {
  EXPECT_EQ(ok({}).kind, Kind::kHelp);
  EXPECT_EQ(ok({"help"}).kind, Kind::kHelp);
  EXPECT_EQ(ok({"version"}).kind, Kind::kVersion);
  EXPECT_EQ(ok({"id"}).kind, Kind::kId);
  EXPECT_EQ(ok({"pair", "--listen"}).kind, Kind::kPairListen);
  const Command pc = ok({"pair", "192.168.1.5:5000"});
  EXPECT_EQ(pc.kind, Kind::kPairConnect);
  EXPECT_EQ(pc.target, "192.168.1.5:5000");
  EXPECT_EQ(ok({"peers"}).kind, Kind::kPeers);
  EXPECT_TRUE(ok({"peers", "--scan"}).options.scan);
  const Command chat = ok({"chat", "laptop", "--host", "10.0.0.2"});
  EXPECT_EQ(chat.kind, Kind::kChat);
  EXPECT_EQ(chat.target, "laptop");
  EXPECT_EQ(chat.options.host, "10.0.0.2");
}

TEST(CliArgs, Options) {
  const Command c = ok({"id", "--name", "my pc", "--port", "5000", "--discovery-port", "5001",
                        "--data-dir", "/tmp/x", "--no-discovery"});
  EXPECT_EQ(c.options.name, "my pc");
  EXPECT_EQ(c.options.port, 5000);
  EXPECT_EQ(c.options.discovery_port, 5001);
  EXPECT_EQ(c.options.data_dir, fs::path("/tmp/x"));
  EXPECT_TRUE(c.options.no_discovery);
  EXPECT_EQ(ok({"id"}).options.port, kDefaultPort);
}

TEST(CliArgs, Errors) {
  EXPECT_TRUE(fails({"bogus"}));
  EXPECT_TRUE(fails({"id", "--bogus"}));
  EXPECT_TRUE(fails({"id", "extra"}));
  EXPECT_TRUE(fails({"id", "--name"}));
  EXPECT_TRUE(fails({"id", "--port", "0"}));
  EXPECT_TRUE(fails({"id", "--port", "70000"}));
  EXPECT_TRUE(fails({"id", "--port", "12x"}));
  EXPECT_TRUE(fails({"pair"}));
  EXPECT_TRUE(fails({"pair", "--listen", "host"}));
  EXPECT_TRUE(fails({"pair", "host:"}));
  EXPECT_TRUE(fails({"chat"}));
  EXPECT_TRUE(fails({"chat", "a", "b"}));
  EXPECT_TRUE(fails({"id", "--listen"}));
  EXPECT_TRUE(fails({"id", "--scan"}));
  EXPECT_TRUE(fails({"peers", "--host", "x"}));
}

TEST(CliArgs, HostPort) {
  auto hp = parse_host_port("pc.local", 47821);
  ASSERT_TRUE(hp);
  EXPECT_EQ(hp->host, "pc.local");
  EXPECT_EQ(hp->port, 47821);
  hp = parse_host_port("10.0.0.1:9", 47821);
  ASSERT_TRUE(hp);
  EXPECT_EQ(hp->host, "10.0.0.1");
  EXPECT_EQ(hp->port, 9);
  hp = parse_host_port("[fe80::1]:600", 47821);
  ASSERT_TRUE(hp);
  EXPECT_EQ(hp->host, "fe80::1");
  EXPECT_EQ(hp->port, 600);
  hp = parse_host_port("fe80::1", 47821);
  ASSERT_TRUE(hp);
  EXPECT_EQ(hp->host, "fe80::1");
  EXPECT_EQ(hp->port, 47821);
  for (const char* bad : {"", ":80", "h:0", "h:x", "[::1", "[]:80", "[::1]x"}) {
    EXPECT_FALSE(parse_host_port(bad, 1)) << bad;
  }
}

// --- output sanitizing (T5) -----------------------------------------------------

TEST(CliOutput, ControlCharactersAreNeutralised) {
  EXPECT_EQ(printable("plain caf\xC3\xA9"), "plain caf\xC3\xA9");
  EXPECT_EQ(printable("\x1b[2Jcleared"), "?[2Jcleared");
  EXPECT_EQ(printable("a\nb\rc\td\x7f"), "a?b?c?d?");
  EXPECT_EQ(printable("csi:\xC2\x9B" "31m"), "csi:?31m");  // C1 CSI
  EXPECT_EQ(printable("\xC2\xA0nbsp"), "\xC2\xA0nbsp");  // not a control
}

TEST(CliOutput, DeviceNames) {
  EXPECT_EQ(sanitize_device_name("desktop-01"), "desktop-01");
  EXPECT_EQ(sanitize_device_name(""), "2link-device");
  EXPECT_EQ(sanitize_device_name("bad\x01name\xFF"), "bad-name-");
  EXPECT_EQ(sanitize_device_name(std::string(80, 'x')), std::string(64, 'x'));
  // A multi-byte character is never cut in half.
  std::string s(63, 'a');
  s += "\xC3\xA9";
  EXPECT_EQ(sanitize_device_name(s), std::string(63, 'a'));
}

TEST(CliOutput, UtcFormat) {
  EXPECT_EQ(format_utc(0), "1970-01-01 00:00 UTC");
  EXPECT_EQ(format_utc(1'795'781'700), "2026-11-27 12:15 UTC");
}

// --- peer lookup --------------------------------------------------------------

class ResolvePeer : public ::testing::Test {
 protected:
  void SetUp() override {
    const auto r = twolink::identity::SecretKey::random();
    std::string tag;
    for (std::size_t i = 0; i < 8; ++i) tag += static_cast<char>('a' + r.bytes()[i] % 26);
    dir_ = fs::temp_directory_path() / ("2link-cli-" + tag);
    ASSERT_EQ(twolink::identity::TrustStore::open(ks_, dir_ / "t.bin", trust_),
              twolink::identity::TrustStoreStatus::kOk);
  }
  void TearDown() override {
    std::error_code ec;
    fs::remove_all(dir_, ec);
  }
  twolink::identity::PeerRecord add(const std::string& name) {
    auto rec = twolink::identity::make_peer_record(
        twolink::crypto::StaticKeyPair::generate().public_key(), name, std::chrono::system_clock::now());
    EXPECT_EQ(trust_->add(rec), twolink::identity::TrustStoreStatus::kOk);
    return rec;
  }
  fs::path dir_;
  twolink::identity::MemoryKeystore ks_;
  std::optional<twolink::identity::TrustStore> trust_;
};

TEST_F(ResolvePeer, ByNameAndIdPrefix) {
  const auto a = add("laptop");
  add("desktop");
  auto m = resolve_peer(*trust_, "laptop");
  ASSERT_EQ(m.result, PeerMatch::Result::kFound);
  EXPECT_EQ(m.matches[0]->device_id, a.device_id);

  const std::string display = twolink::identity::display_form(a.device_id);  // xxxx-xxxx-...
  m = resolve_peer(*trust_, display);
  ASSERT_EQ(m.result, PeerMatch::Result::kFound);
  EXPECT_EQ(m.matches[0]->device_id, a.device_id);
  m = resolve_peer(*trust_, twolink::identity::to_hex(a.device_id).substr(0, 12));
  EXPECT_EQ(m.result, PeerMatch::Result::kFound);

  EXPECT_EQ(resolve_peer(*trust_, "nobody").result, PeerMatch::Result::kNotFound);
  EXPECT_EQ(resolve_peer(*trust_, "abc").result, PeerMatch::Result::kNotFound);  // < 4 hex digits
}

TEST_F(ResolvePeer, AmbiguousNameIsRefused) {
  add("pc");
  add("pc");
  EXPECT_EQ(resolve_peer(*trust_, "pc").result, PeerMatch::Result::kAmbiguous);
}

}  // namespace
