// load_or_create_identity (spec §4.1, §4.8).

#include "twolink/identity/identity.hpp"

#include <filesystem>
#include <string>

#include <gtest/gtest.h>

namespace {

using namespace twolink::identity;

// Keystore with scripted results, to check what load_or_create_identity does.
class ScriptedKeystore final : public Keystore {
 public:
  KeystoreStatus load_result = KeystoreStatus::kNotFound;
  KeystoreStatus store_result = KeystoreStatus::kOk;
  int loads = 0;
  int stores = 0;
  MemoryKeystore backing;  // used once load_result becomes kOk

  KeystoreStatus load(std::string_view name, std::optional<SecretKey>& out) override {
    ++loads;
    if (load_result != KeystoreStatus::kOk) return load_result;
    return backing.load(name, out);
  }
  KeystoreStatus store(std::string_view, const SecretKey&) override {
    ++stores;
    return store_result;
  }
};

TEST(Identity, CreatedOnFirstRunThenLoaded) {
  MemoryKeystore ks;
  std::optional<Identity> first;
  bool created = false;
  ASSERT_EQ(load_or_create_identity(ks, first, &created), KeystoreStatus::kOk);
  EXPECT_TRUE(created);
  EXPECT_EQ(first->device_id, device_id_from_key(first->key.public_key()));

  std::optional<Identity> second;
  ASSERT_EQ(load_or_create_identity(ks, second, &created), KeystoreStatus::kOk);
  EXPECT_FALSE(created);
  EXPECT_EQ(second->device_id, first->device_id);
  EXPECT_EQ(second->key.public_key(), first->key.public_key());
}

TEST(Identity, DamagedKeyIsNeverReplaced) {
  for (const KeystoreStatus bad : {KeystoreStatus::kCorrupt, KeystoreStatus::kInsecurePermissions,
                                   KeystoreStatus::kIoError}) {
    ScriptedKeystore ks;
    ks.load_result = bad;
    std::optional<Identity> out;
    EXPECT_EQ(load_or_create_identity(ks, out), bad);
    EXPECT_EQ(ks.stores, 0) << to_string(bad);
    EXPECT_FALSE(out.has_value());
  }
}

TEST(Identity, StoreFailureIsReported) {
  ScriptedKeystore ks;
  ks.store_result = KeystoreStatus::kIoError;
  std::optional<Identity> out;
  EXPECT_EQ(load_or_create_identity(ks, out), KeystoreStatus::kIoError);
  EXPECT_FALSE(out.has_value());
}

TEST(Identity, ConcurrentCreationUsesTheStoredKey) {
  // Another process stored a key between our load and our store.
  ScriptedKeystore ks;
  const SecretKey theirs = SecretKey::random();
  ASSERT_EQ(ks.backing.store(kIdentitySecretName, theirs), KeystoreStatus::kOk);
  ks.store_result = KeystoreStatus::kAlreadyExists;

  struct Racer final : Keystore {
    ScriptedKeystore& inner;
    explicit Racer(ScriptedKeystore& k) : inner(k) {}
    KeystoreStatus load(std::string_view name, std::optional<SecretKey>& out) override {
      const KeystoreStatus s = inner.load(name, out);
      inner.load_result = KeystoreStatus::kOk;  // the other process wins after our first look
      return s;
    }
    KeystoreStatus store(std::string_view name, const SecretKey& s) override {
      return inner.store(name, s);
    }
  } racer(ks);

  std::optional<Identity> out;
  bool created = true;
  ASSERT_EQ(load_or_create_identity(racer, out, &created), KeystoreStatus::kOk);
  EXPECT_FALSE(created);
  EXPECT_EQ(out->key.public_key(),
            twolink::crypto::StaticKeyPair::from_private_key(theirs.bytes()).public_key());
}

TEST(Identity, PersistsInAFileKeystore) {
  namespace fs = std::filesystem;
  const SecretKey r = SecretKey::random();
  const fs::path dir = fs::temp_directory_path() /
                       ("2link-identity-test-" + std::to_string(r.bytes()[0]) + std::to_string(r.bytes()[1]));
  fs::remove_all(dir);
  std::optional<Identity> a;
  std::optional<Identity> b;
  {
    FileKeystore ks(dir);
    ASSERT_EQ(load_or_create_identity(ks, a), KeystoreStatus::kOk);
  }
  {
    FileKeystore ks(dir);
    ASSERT_EQ(load_or_create_identity(ks, b), KeystoreStatus::kOk);
  }
  EXPECT_EQ(a->device_id, b->device_id);
  fs::remove_all(dir);
}

TEST(Identity, DefaultDataDirEndsIn2link) {
  const auto dir = default_data_dir();
  ASSERT_TRUE(dir.has_value());  // HOME / LOCALAPPDATA is set on CI and dev machines
  EXPECT_EQ(dir->filename(), "2link");
}

}  // namespace
