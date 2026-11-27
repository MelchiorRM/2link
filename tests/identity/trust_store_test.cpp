// Trust store, spec v0.1.3 §4.7 (threat model L2, H4, H5).

#include "twolink/identity/trust_store.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#include "twolink/crypto/keys.hpp"

namespace {

namespace fs = std::filesystem;
using namespace twolink::identity;
using twolink::crypto::PublicKey;
using twolink::crypto::StaticKeyPair;
using Bytes = std::vector<std::uint8_t>;

const auto kWhen = std::chrono::system_clock::time_point{} + std::chrono::seconds{1'790'000'000};

Bytes read_file(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  return Bytes(std::istreambuf_iterator<char>(in), {});
}

void write_file(const fs::path& p, const Bytes& data) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

PeerRecord peer(std::string name) {
  return make_peer_record(StaticKeyPair::generate().public_key(), std::move(name), kWhen);
}

SecretKey key_of(std::uint8_t v) {
  std::array<std::uint8_t, kSecretSize> b{};
  b.fill(v);
  return SecretKey::from_bytes(b);
}

// --- records --------------------------------------------------------------------

TEST(PeerRecord, DeviceIdIsDerivedFromTheKey) {
  const StaticKeyPair k = StaticKeyPair::generate();
  const PeerRecord r = make_peer_record(k.public_key(), "laptop", kWhen);
  EXPECT_EQ(r.device_id, device_id_from_key(k.public_key()));
  EXPECT_EQ(r.static_key, k.public_key());
  EXPECT_EQ(r.first_paired_at, 1'790'000'000);
  EXPECT_EQ(r.trust, Trust::kVerified);
}

// --- file format (L2) -------------------------------------------------------------

TEST(TrustFile, RoundTrip) {
  const SecretKey key = key_of(7);
  std::vector<PeerRecord> peers{peer("a"), peer("caf\xC3\xA9"), peer(std::string(64, 'z'))};
  peers[1].first_paired_at = -5;  // before 1970 survives the u64 encoding
  std::vector<PeerRecord> got;
  ASSERT_EQ(detail::decode_trust_file(detail::encode_trust_file(peers, key), key, got),
            TrustStoreStatus::kOk);
  EXPECT_EQ(got, peers);
}

TEST(TrustFile, EmptyStoreRoundTrips) {
  const SecretKey key = key_of(7);
  std::vector<PeerRecord> got{peer("x")};
  ASSERT_EQ(detail::decode_trust_file(detail::encode_trust_file({}, key), key, got),
            TrustStoreStatus::kOk);
  EXPECT_TRUE(got.empty());
}

TEST(TrustFile, EveryBitFlipIsDetected) {  // L2
  const SecretKey key = key_of(7);
  const std::vector<PeerRecord> peers{peer("a"), peer("b")};
  const Bytes file = detail::encode_trust_file(peers, key);
  for (std::size_t i = 0; i < file.size(); ++i) {
    for (int bit = 0; bit < 8; ++bit) {
      Bytes bad = file;
      bad[i] = static_cast<std::uint8_t>(bad[i] ^ (1u << bit));
      std::vector<PeerRecord> got;
      ASSERT_EQ(detail::decode_trust_file(bad, key, got), TrustStoreStatus::kCorrupt)
          << "byte " << i << " bit " << bit;
      ASSERT_TRUE(got.empty());
    }
  }
}

TEST(TrustFile, TruncatedOrExtendedFileIsDetected) {
  const SecretKey key = key_of(7);
  const Bytes file = detail::encode_trust_file(std::vector<PeerRecord>{peer("a")}, key);
  std::vector<PeerRecord> got;
  for (std::size_t n = 0; n < file.size(); ++n) {
    EXPECT_EQ(detail::decode_trust_file(std::span(file).first(n), key, got),
              TrustStoreStatus::kCorrupt);
  }
  Bytes longer = file;
  longer.push_back(0);
  EXPECT_EQ(detail::decode_trust_file(longer, key, got), TrustStoreStatus::kCorrupt);
}

TEST(TrustFile, WrongKeyIsDetected) {
  const Bytes file = detail::encode_trust_file(std::vector<PeerRecord>{peer("a")}, key_of(7));
  std::vector<PeerRecord> got;
  EXPECT_EQ(detail::decode_trust_file(file, key_of(8), got), TrustStoreStatus::kCorrupt);
}

TEST(TrustFile, AuthenticButInvalidRecordsAreRejected) {
  // Even with a valid MAC (a bug, or a key leak), the parser stays strict.
  const SecretKey key = key_of(7);
  std::vector<PeerRecord> got;

  PeerRecord forged = peer("a");
  forged.static_key = StaticKeyPair::generate().public_key();  // device_id no longer matches
  EXPECT_EQ(detail::decode_trust_file(detail::encode_trust_file(std::vector{forged}, key), key, got),
            TrustStoreStatus::kCorrupt);

  const PeerRecord dup = peer("a");
  EXPECT_EQ(detail::decode_trust_file(detail::encode_trust_file(std::vector{dup, dup}, key), key,
                                      got),
            TrustStoreStatus::kCorrupt);

  for (const std::string& name : {std::string(), std::string("\xFF")}) {
    PeerRecord bad = peer("x");
    bad.name = name;
    EXPECT_EQ(detail::decode_trust_file(detail::encode_trust_file(std::vector{bad}, key), key, got),
              TrustStoreStatus::kCorrupt);
  }
}

// --- TrustStore on disk -------------------------------------------------------------

class TrustStoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const SecretKey r = SecretKey::random();
    std::string tag;
    for (std::size_t i = 0; i < 6; ++i) tag += static_cast<char>('a' + r.bytes()[i] % 26);
    root_ = fs::temp_directory_path() / ("2link-trust-test-" + tag);
    fs::remove_all(root_);
    fs::create_directories(root_);
    file_ = root_ / "data" / "trust-store.bin";
  }
  void TearDown() override {
    std::error_code ec;
    fs::remove_all(root_, ec);
  }

  std::optional<TrustStore> open() {
    std::optional<TrustStore> ts;
    EXPECT_EQ(TrustStore::open(keystore_, file_, ts), TrustStoreStatus::kOk);
    return ts;
  }

  fs::path root_;
  fs::path file_;
  MemoryKeystore keystore_;
};

TEST_F(TrustStoreTest, StartsEmptyAndCreatesItsKey) {
  auto ts = open();
  ASSERT_TRUE(ts);
  EXPECT_TRUE(ts->peers().empty());
  EXPECT_FALSE(fs::exists(file_));  // written on the first change
  std::optional<SecretKey> key;
  EXPECT_EQ(keystore_.load(kTrustStoreSecretName, key), KeystoreStatus::kOk);
}

TEST_F(TrustStoreTest, PersistsAcrossOpens) {
  const PeerRecord a = peer("alpha");
  const PeerRecord b = peer("beta");
  {
    auto ts = open();
    ASSERT_EQ(ts->add(a), TrustStoreStatus::kOk);
    ASSERT_EQ(ts->add(b), TrustStoreStatus::kOk);
  }
  auto ts = open();
  ASSERT_TRUE(ts);
  EXPECT_EQ(ts->peers(), (std::vector<PeerRecord>{a, b}));
}

TEST_F(TrustStoreTest, Lookups) {
  auto ts = open();
  const PeerRecord a = peer("laptop");
  const PeerRecord b = peer("laptop");  // same name, different key
  ASSERT_EQ(ts->add(a), TrustStoreStatus::kOk);
  ASSERT_EQ(ts->add(b), TrustStoreStatus::kOk);
  ASSERT_TRUE(ts->find(a.device_id));
  EXPECT_EQ(ts->find(a.device_id)->static_key, a.static_key);
  ASSERT_TRUE(ts->find_by_key(b.static_key));
  EXPECT_EQ(ts->find_by_key(b.static_key)->device_id, b.device_id);
  EXPECT_FALSE(ts->find_by_key(StaticKeyPair::generate().public_key()));  // H5: unknown key
  EXPECT_EQ(ts->find_by_name("laptop").size(), 2u);                      // H4: name match
  EXPECT_TRUE(ts->find_by_name("desktop").empty());
}

TEST_F(TrustStoreTest, RePairReplacesTheOldRecord) {  // §4.8
  auto ts = open();
  const PeerRecord old_key = peer("laptop");
  ASSERT_EQ(ts->add(old_key), TrustStoreStatus::kOk);
  const PeerRecord new_key = peer("laptop");
  ASSERT_EQ(ts->add(new_key), TrustStoreStatus::kOk);
  ASSERT_EQ(ts->remove(old_key.device_id), TrustStoreStatus::kOk);
  EXPECT_EQ(ts->peers(), std::vector<PeerRecord>{new_key});
  EXPECT_EQ(ts->remove(old_key.device_id), TrustStoreStatus::kOk);  // already gone

  // Adding the same device again updates it in place.
  PeerRecord renamed = new_key;
  renamed.name = "work laptop";
  ASSERT_EQ(ts->add(renamed), TrustStoreStatus::kOk);
  EXPECT_EQ(ts->peers(), std::vector<PeerRecord>{renamed});
}

TEST_F(TrustStoreTest, InvalidRecordsAreRefused) {
  auto ts = open();
  PeerRecord forged = peer("x");
  forged.device_id[0] ^= 1;  // a device_id not derived from the key
  EXPECT_EQ(ts->add(forged), TrustStoreStatus::kInvalidRecord);
  EXPECT_EQ(ts->add(peer("")), TrustStoreStatus::kInvalidRecord);
  EXPECT_EQ(ts->add(peer(std::string(65, 'x'))), TrustStoreStatus::kInvalidRecord);
  EXPECT_TRUE(ts->peers().empty());
  EXPECT_FALSE(fs::exists(file_));
}

TEST_F(TrustStoreTest, EditedFileIsRefused) {  // L2
  {
    auto ts = open();
    ASSERT_EQ(ts->add(peer("alpha")), TrustStoreStatus::kOk);
  }
  Bytes bytes = read_file(file_);
  bytes[20] ^= 1;
  write_file(file_, bytes);
#ifndef _WIN32
  ASSERT_EQ(::chmod(file_.c_str(), 0600), 0);
#endif
  std::optional<TrustStore> ts;
  EXPECT_EQ(TrustStore::open(keystore_, file_, ts), TrustStoreStatus::kCorrupt);
  EXPECT_FALSE(ts);
}

TEST_F(TrustStoreTest, AttackerKeyCannotBeAddedWithoutTheMacKey) {  // L2
  {
    auto ts = open();
    ASSERT_EQ(ts->add(peer("alpha")), TrustStoreStatus::kOk);
  }
  // A well-formed file with an attacker's record, MACed with a guessed key.
  write_file(file_, detail::encode_trust_file(std::vector{peer("alpha")}, key_of(0)));
#ifndef _WIN32
  ASSERT_EQ(::chmod(file_.c_str(), 0600), 0);
#endif
  std::optional<TrustStore> ts;
  EXPECT_EQ(TrustStore::open(keystore_, file_, ts), TrustStoreStatus::kCorrupt);
}

TEST_F(TrustStoreTest, FileWithoutItsKeyIsRefused) {
  {
    auto ts = open();
    ASSERT_EQ(ts->add(peer("alpha")), TrustStoreStatus::kOk);
  }
  MemoryKeystore other;  // the key is gone
  std::optional<TrustStore> ts;
  EXPECT_EQ(TrustStore::open(other, file_, ts), TrustStoreStatus::kKeyUnavailable);
  std::optional<SecretKey> key;
  EXPECT_EQ(other.load(kTrustStoreSecretName, key), KeystoreStatus::kNotFound);  // not replaced
}

TEST_F(TrustStoreTest, OversizedFileIsRefusedWithoutReadingIt) {
  fs::create_directories(file_.parent_path());
  write_file(file_, Bytes(200 * 1024, 0));
#ifndef _WIN32
  ASSERT_EQ(::chmod(file_.c_str(), 0600), 0);
#endif
  std::optional<TrustStore> ts;
  EXPECT_EQ(TrustStore::open(keystore_, file_, ts), TrustStoreStatus::kCorrupt);
}

TEST_F(TrustStoreTest, LeavesNoTemporaryFiles) {
  auto ts = open();
  for (int i = 0; i < 3; ++i) ASSERT_EQ(ts->add(peer("p" + std::to_string(i))), TrustStoreStatus::kOk);
  std::vector<fs::path> files;
  for (const auto& e : fs::directory_iterator(file_.parent_path())) files.push_back(e.path());
  EXPECT_EQ(files, std::vector<fs::path>{file_});
}

#ifndef _WIN32

mode_t mode_of(const fs::path& p) {
  struct stat st {};
  EXPECT_EQ(::stat(p.c_str(), &st), 0);
  return st.st_mode & 07777;
}

TEST_F(TrustStoreTest, FileIsOwnerOnly) {  // L2
  auto ts = open();
  ASSERT_EQ(ts->add(peer("alpha")), TrustStoreStatus::kOk);
  EXPECT_EQ(mode_of(file_), 0600u);
  EXPECT_EQ(mode_of(file_.parent_path()), 0700u);
}

TEST_F(TrustStoreTest, FileReadableByOthersIsRefused) {
  {
    auto ts = open();
    ASSERT_EQ(ts->add(peer("alpha")), TrustStoreStatus::kOk);
  }
  ASSERT_EQ(::chmod(file_.c_str(), 0644), 0);
  std::optional<TrustStore> ts;
  EXPECT_EQ(TrustStore::open(keystore_, file_, ts), TrustStoreStatus::kInsecurePermissions);
}

TEST_F(TrustStoreTest, SymlinkIsRefused) {
  {
    auto ts = open();
    ASSERT_EQ(ts->add(peer("alpha")), TrustStoreStatus::kOk);
  }
  const fs::path elsewhere = root_ / "elsewhere.bin";
  fs::rename(file_, elsewhere);
  fs::create_symlink(elsewhere, file_);
  std::optional<TrustStore> ts;
  EXPECT_EQ(TrustStore::open(keystore_, file_, ts), TrustStoreStatus::kInsecurePermissions);
}

TEST_F(TrustStoreTest, FailedSaveLeavesMemoryUnchanged) {
  auto ts = open();
  const PeerRecord a = peer("alpha");
  ASSERT_EQ(ts->add(a), TrustStoreStatus::kOk);
  ASSERT_EQ(::chmod(file_.parent_path().c_str(), 0770), 0);  // others may write: refuse
  EXPECT_EQ(ts->add(peer("beta")), TrustStoreStatus::kInsecurePermissions);
  EXPECT_EQ(ts->remove(a.device_id), TrustStoreStatus::kInsecurePermissions);
  EXPECT_EQ(ts->peers(), std::vector<PeerRecord>{a});
  ASSERT_EQ(::chmod(file_.parent_path().c_str(), 0700), 0);
}

#endif

}  // namespace
