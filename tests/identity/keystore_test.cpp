// Keystore backends (threat model L1, L4).

#include "twolink/identity/keystore.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#include "twolink/crypto/keys.hpp"

namespace {

namespace fs = std::filesystem;
using namespace twolink::identity;
using Bytes = std::vector<std::uint8_t>;

bool same(const SecretKey& a, const SecretKey& b) {
  return std::equal(a.bytes().begin(), a.bytes().end(), b.bytes().begin());
}

Bytes read_file(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  return Bytes(std::istreambuf_iterator<char>(in), {});
}

void write_file(const fs::path& p, const Bytes& data) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

// --- names, SecretKey, MemoryKeystore -------------------------------------------------

TEST(Keystore, SecretNamesAreRestricted) {
  EXPECT_TRUE(is_valid_secret_name("identity"));
  EXPECT_TRUE(is_valid_secret_name("trust-store-2"));
  EXPECT_TRUE(is_valid_secret_name(std::string(32, 'a')));
  for (const char* bad : {"", "Identity", "../x", "a/b", "a\\b", "a.key", "a b"}) {
    EXPECT_FALSE(is_valid_secret_name(bad)) << bad;
  }
  EXPECT_FALSE(is_valid_secret_name(std::string(33, 'a')));
}

TEST(SecretKey, MovedFromIsWiped) {  // L4
  SecretKey a = SecretKey::random();
  SecretKey b = std::move(a);
  const auto bytes = a.bytes();  // NOLINT(bugprone-use-after-move): checking the wipe
  EXPECT_TRUE(std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t x) { return x == 0; }));
  EXPECT_FALSE(std::all_of(b.bytes().begin(), b.bytes().end(), [](std::uint8_t x) { return x == 0; }));
}

TEST(MemoryKeystore, RoundTripAndNoOverwrite) {
  MemoryKeystore ks;
  std::optional<SecretKey> out;
  EXPECT_EQ(ks.load("identity", out), KeystoreStatus::kNotFound);
  const SecretKey s = SecretKey::random();
  ASSERT_EQ(ks.store("identity", s), KeystoreStatus::kOk);
  EXPECT_EQ(ks.store("identity", SecretKey::random()), KeystoreStatus::kAlreadyExists);
  ASSERT_EQ(ks.load("identity", out), KeystoreStatus::kOk);
  EXPECT_TRUE(same(*out, s));
  EXPECT_EQ(ks.store("../x", s), KeystoreStatus::kInvalidName);
}

// --- FileKeystore, every platform -------------------------------------------------------

class FileKeystoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const SecretKey r = SecretKey::random();
    std::string tag;
    for (std::size_t i = 0; i < 6; ++i) tag += static_cast<char>('a' + r.bytes()[i] % 26);
    root_ = fs::temp_directory_path() / ("2link-keystore-test-" + tag);
    fs::remove_all(root_);
    fs::create_directories(root_);
    dir_ = root_ / "keys";
  }
  void TearDown() override {
    std::error_code ec;
#ifndef _WIN32
    fs::permissions(dir_, fs::perms::owner_all, ec);  // in case a test changed it
#endif
    fs::remove_all(root_, ec);
  }

  fs::path root_;
  fs::path dir_;
};

TEST_F(FileKeystoreTest, RoundTripAcrossInstances) {
  const SecretKey s = SecretKey::random();
  ASSERT_EQ(FileKeystore(dir_).store("identity", s), KeystoreStatus::kOk);
  std::optional<SecretKey> out;
  ASSERT_EQ(FileKeystore(dir_).load("identity", out), KeystoreStatus::kOk);
  EXPECT_TRUE(same(*out, s));
}

TEST_F(FileKeystoreTest, MissingSecretIsNotFound) {
  std::optional<SecretKey> out;
  EXPECT_EQ(FileKeystore(dir_).load("identity", out), KeystoreStatus::kNotFound);
  EXPECT_FALSE(out.has_value());
}

TEST_F(FileKeystoreTest, NeverOverwrites) {
  FileKeystore ks(dir_);
  const SecretKey s = SecretKey::random();
  ASSERT_EQ(ks.store("identity", s), KeystoreStatus::kOk);
  EXPECT_EQ(ks.store("identity", SecretKey::random()), KeystoreStatus::kAlreadyExists);
  std::optional<SecretKey> out;
  ASSERT_EQ(ks.load("identity", out), KeystoreStatus::kOk);
  EXPECT_TRUE(same(*out, s));
}

TEST_F(FileKeystoreTest, LeavesNoTemporaryFiles) {
  FileKeystore ks(dir_);
  ASSERT_EQ(ks.store("identity", SecretKey::random()), KeystoreStatus::kOk);
  ASSERT_EQ(ks.store("trust-store", SecretKey::random()), KeystoreStatus::kOk);
  std::vector<std::string> names;
  for (const auto& e : fs::directory_iterator(dir_)) names.push_back(e.path().filename().string());
  std::sort(names.begin(), names.end());
  EXPECT_EQ(names, (std::vector<std::string>{"identity.key", "trust-store.key"}));
}

TEST_F(FileKeystoreTest, SecretIsNotStoredInTheClear) {
  FileKeystore ks(dir_);
  const SecretKey s = SecretKey::random();
  ASSERT_EQ(ks.store("identity", s), KeystoreStatus::kOk);
  const Bytes file = read_file(ks.path_for("identity"));
#ifdef _WIN32
  // DPAPI: the raw secret must not appear anywhere in the file.
  EXPECT_EQ(std::search(file.begin(), file.end(), s.bytes().begin(), s.bytes().end()), file.end());
#else
  // POSIX: stored as is; confidentiality comes from permissions (checked below).
  EXPECT_EQ(file.size(), 72u);
#endif
}

TEST_F(FileKeystoreTest, DamagedFileIsCorrupt) {
  FileKeystore ks(dir_);
  ASSERT_EQ(ks.store("identity", SecretKey::random()), KeystoreStatus::kOk);
  const fs::path p = ks.path_for("identity");
  const Bytes good = read_file(p);
  std::optional<SecretKey> out;

  auto expect_corrupt = [&](const Bytes& damaged, const char* what) {
    write_file(p, damaged);
    out.reset();
    EXPECT_EQ(ks.load("identity", out), KeystoreStatus::kCorrupt) << what;
    EXPECT_FALSE(out.has_value()) << what;
  };

  // Last byte: the checksum (POSIX) or DPAPI's MAC (Windows). Bytes in the
  // DPAPI blob header are not authenticated and do not change the secret.
  Bytes last = good;
  last.back() ^= 0x01;
  expect_corrupt(last, "last byte flipped");
#ifndef _WIN32
  Bytes secret_byte = good;
  secret_byte[20] ^= 0x01;  // inside the secret
  expect_corrupt(secret_byte, "secret byte flipped");
#endif
  Bytes bad_magic = good;
  bad_magic[0] = 'X';
  expect_corrupt(bad_magic, "bad magic");
  expect_corrupt(Bytes(good.begin(), good.begin() + 10), "truncated");
}

TEST_F(FileKeystoreTest, InvalidNamesNeverTouchTheDisk) {
  FileKeystore ks(dir_);
  std::optional<SecretKey> out;
  EXPECT_EQ(ks.store("../escape", SecretKey::random()), KeystoreStatus::kInvalidName);
  EXPECT_EQ(ks.load("../escape", out), KeystoreStatus::kInvalidName);
  EXPECT_FALSE(fs::exists(dir_));
  EXPECT_FALSE(fs::exists(root_ / "escape.key"));
}

// --- FileKeystore, POSIX permissions (L1) --------------------------------------------------

#ifndef _WIN32

mode_t mode_of(const fs::path& p) {
  struct stat st {};
  EXPECT_EQ(::lstat(p.c_str(), &st), 0);
  return st.st_mode & 07777;
}

TEST_F(FileKeystoreTest, FileIsOwnerOnlyInsideOwnerOnlyDirectory) {
  FileKeystore ks(dir_);
  ASSERT_EQ(ks.store("identity", SecretKey::random()), KeystoreStatus::kOk);
  EXPECT_EQ(mode_of(ks.path_for("identity")), 0600u);
  EXPECT_EQ(mode_of(dir_), 0700u);
}

TEST_F(FileKeystoreTest, RefusesFileReadableByOthers) {
  FileKeystore ks(dir_);
  ASSERT_EQ(ks.store("identity", SecretKey::random()), KeystoreStatus::kOk);
  std::optional<SecretKey> out;
  for (const mode_t m : {0640u, 0604u, 0660u}) {
    ASSERT_EQ(::chmod(ks.path_for("identity").c_str(), m), 0);
    EXPECT_EQ(ks.load("identity", out), KeystoreStatus::kInsecurePermissions) << std::oct << m;
  }
  EXPECT_FALSE(out.has_value());
}

TEST_F(FileKeystoreTest, RefusesSymlink) {
  FileKeystore ks(dir_);
  ASSERT_EQ(ks.store("identity", SecretKey::random()), KeystoreStatus::kOk);
  const fs::path elsewhere = root_ / "elsewhere.key";
  fs::rename(ks.path_for("identity"), elsewhere);
  fs::create_symlink(elsewhere, ks.path_for("identity"));
  std::optional<SecretKey> out;
  EXPECT_EQ(ks.load("identity", out), KeystoreStatus::kInsecurePermissions);
}

TEST_F(FileKeystoreTest, RefusesDirectoryWritableByOthers) {
  fs::create_directories(dir_);
  ASSERT_EQ(::chmod(dir_.c_str(), 0770), 0);
  EXPECT_EQ(FileKeystore(dir_).store("identity", SecretKey::random()),
            KeystoreStatus::kInsecurePermissions);
}

TEST_F(FileKeystoreTest, RefusesNonRegularFile) {
  FileKeystore ks(dir_);
  ASSERT_EQ(ks.store("trust-store", SecretKey::random()), KeystoreStatus::kOk);  // creates dir
  fs::create_directory(ks.path_for("identity"));
  ASSERT_EQ(::chmod(ks.path_for("identity").c_str(), 0700), 0);
  std::optional<SecretKey> out;
  EXPECT_EQ(ks.load("identity", out), KeystoreStatus::kInsecurePermissions);
}

#endif

}  // namespace
