// Device table, spec v0.1.3 §8 (threat model D1, D4).

#include "twolink/discovery/device_table.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <optional>
#include <set>
#include <string>

#include "twolink/crypto/keys.hpp"
#include "twolink/identity/keystore.hpp"

namespace {

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using namespace twolink::discovery;
using twolink::crypto::StaticKeyPair;
using twolink::identity::DeviceId;

const Clock::time_point kT0{};

Announcement device(std::string name = "dev") {
  return make_announcement(std::move(name), StaticKeyPair::generate().public_key(), 47821);
}

TEST(DeviceTable, AddsRefreshesAndExpires) {
  DeviceTable t;
  const Announcement a = device("a");
  EXPECT_EQ(t.update(a, "10.0.0.1", kT0), DeviceTable::Update::kAdded);
  Announcement renamed = a;
  renamed.device_name = "a2";
  renamed.tcp_port = 5000;
  EXPECT_EQ(t.update(renamed, "10.0.0.9", kT0 + 5s), DeviceTable::Update::kRefreshed);
  const auto d = t.find(a.device_id, kT0 + 5s);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->announcement.device_name, "a2");
  EXPECT_EQ(d->announcement.tcp_port, 5000);
  EXPECT_EQ(d->address, "10.0.0.9");
  // 15 s without an announcement: gone.
  EXPECT_TRUE(t.find(a.device_id, kT0 + 19s));
  EXPECT_FALSE(t.find(a.device_id, kT0 + 20s));
  EXPECT_TRUE(t.devices(kT0 + 20s).empty());
  t.expire(kT0 + 20s);
  EXPECT_EQ(t.size(), 0u);
}

TEST(DeviceTable, ListsMostRecentFirst) {
  DeviceTable t;
  const Announcement a = device("a");
  const Announcement b = device("b");
  ASSERT_EQ(t.update(a, "1", kT0), DeviceTable::Update::kAdded);
  ASSERT_EQ(t.update(b, "2", kT0 + 1s), DeviceTable::Update::kAdded);
  const auto list = t.devices(kT0 + 1s);
  ASSERT_EQ(list.size(), 2u);
  EXPECT_EQ(list[0].announcement.device_name, "b");
}

TEST(DeviceTable, FloodFromManySourcesStaysBounded) {  // D4
  DeviceTable t;
  for (int i = 0; i < 10000; ++i) {
    static_cast<void>(t.update(device(), "10." + std::to_string(i / 65536) + "." +
                                             std::to_string((i / 256) % 256) + "." +
                                             std::to_string(i % 256),
                               kT0 + std::chrono::milliseconds(i)));
  }
  EXPECT_LE(t.size(), 128u);
  EXPECT_LE(t.source_count(), 256u);
}

TEST(DeviceTable, FloodFromOneSourceIsRateLimited) {  // D4
  DeviceTable t;
  int added = 0;
  int limited = 0;
  for (int i = 0; i < 100; ++i) {
    const auto u = t.update(device(), "10.0.0.66", kT0);
    added += u == DeviceTable::Update::kAdded;
    limited += u == DeviceTable::Update::kRateLimited;
  }
  EXPECT_EQ(added, 8);
  EXPECT_EQ(limited, 92);
  EXPECT_EQ(t.update(device(), "10.0.0.66", kT0 + 5s), DeviceTable::Update::kAdded);  // new window
  EXPECT_EQ(t.update(device(), "10.0.0.67", kT0), DeviceTable::Update::kAdded);       // other source
}

TEST(DeviceTable, FloodCannotEvictPairedDevices) {  // D4
  std::set<DeviceId> paired;
  DeviceTable t({.max_devices = 4}, [&](const Announcement& a) { return paired.contains(a.device_id); });
  const Announcement p1 = device("p1");
  const Announcement p2 = device("p2");
  paired = {p1.device_id, p2.device_id};
  ASSERT_EQ(t.update(p1, "1", kT0), DeviceTable::Update::kAdded);
  ASSERT_EQ(t.update(p2, "2", kT0), DeviceTable::Update::kAdded);
  for (int i = 0; i < 50; ++i) {
    static_cast<void>(t.update(device(), "x" + std::to_string(i), kT0 + 1s));
  }
  EXPECT_EQ(t.size(), 4u);
  EXPECT_TRUE(t.find(p1.device_id, kT0 + 1s));
  EXPECT_TRUE(t.find(p2.device_id, kT0 + 1s));

  // A table full of paired devices refuses unpaired newcomers.
  DeviceTable full({.max_devices = 2}, [&](const Announcement& a) { return paired.contains(a.device_id); });
  ASSERT_EQ(full.update(p1, "1", kT0), DeviceTable::Update::kAdded);
  ASSERT_EQ(full.update(p2, "2", kT0), DeviceTable::Update::kAdded);
  EXPECT_EQ(full.update(device(), "3", kT0), DeviceTable::Update::kDropped);
}

TEST(DeviceTable, WhenFullTheOldestUnpairedGoes) {
  DeviceTable t({.max_devices = 2});
  const Announcement a = device("a");
  const Announcement b = device("b");
  const Announcement c = device("c");
  ASSERT_EQ(t.update(a, "1", kT0), DeviceTable::Update::kAdded);
  ASSERT_EQ(t.update(b, "2", kT0 + 1s), DeviceTable::Update::kAdded);
  ASSERT_EQ(t.update(c, "3", kT0 + 2s), DeviceTable::Update::kAdded);
  EXPECT_FALSE(t.find(a.device_id, kT0 + 2s));
  EXPECT_TRUE(t.find(b.device_id, kT0 + 2s));
  EXPECT_TRUE(t.find(c.device_id, kT0 + 2s));
}

// --- classification against the trust store (D1) ----------------------------------

class ClassifyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const auto r = twolink::identity::SecretKey::random();
    std::string tag;
    for (std::size_t i = 0; i < 8; ++i) tag += static_cast<char>('a' + r.bytes()[i] % 26);
    dir_ = fs::temp_directory_path() / ("2link-classify-" + tag);
    ASSERT_EQ(twolink::identity::TrustStore::open(keystore_, dir_ / "trust.bin", trust_),
              twolink::identity::TrustStoreStatus::kOk);
  }
  void TearDown() override {
    std::error_code ec;
    fs::remove_all(dir_, ec);
  }
  fs::path dir_;
  twolink::identity::MemoryKeystore keystore_;
  std::optional<twolink::identity::TrustStore> trust_;
};

TEST_F(ClassifyTest, PairedUnverifiedAndNameClash) {
  const StaticKeyPair peer = StaticKeyPair::generate();
  ASSERT_EQ(trust_->add(twolink::identity::make_peer_record(peer.public_key(), "beta",
                                                            std::chrono::system_clock::now())),
            twolink::identity::TrustStoreStatus::kOk);
  EXPECT_EQ(classify(make_announcement("beta", peer.public_key(), 1), *trust_), DeviceStatus::kPaired);
  // The trusted key under another name is still that device.
  EXPECT_EQ(classify(make_announcement("renamed", peer.public_key(), 1), *trust_),
            DeviceStatus::kPaired);
  EXPECT_EQ(classify(device("gamma"), *trust_), DeviceStatus::kUnverified);
  // A foreign key using a trusted peer's name: unverified, with a warning (D1).
  EXPECT_EQ(classify(device("beta"), *trust_), DeviceStatus::kUnverifiedNameClash);
}

}  // namespace
