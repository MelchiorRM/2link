/* 2Link additions to noise-c (threat model X2). C API, used only by src/crypto. */
#pragma once

#include <stdint.h>

#include <noise/protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Noise spec Rekey(), required by 2Link spec §5.1 and §5.4:
 *   k' = first 32 bytes of ENCRYPT(k, n = 2^64 - 1, ad = empty, plaintext = 32 zero bytes)
 * The nonce counter n is left unchanged. noise-c has no Rekey(), so this uses
 * noise-c's internal CipherState hooks (depends on src/protocol/internal.h at
 * the pinned commit; tests/crypto checks the result against libsodium).
 *
 * Returns NOISE_ERROR_NONE, NOISE_ERROR_INVALID_PARAM, NOISE_ERROR_INVALID_STATE
 * (no key) or NOISE_ERROR_NOT_APPLICABLE (key length is not 32 bytes). */
int twolink_noise_cipherstate_rekey(NoiseCipherState *state);

/* Current nonce counter n (noise-c has no getter). 0 for NULL. */
uint64_t twolink_noise_cipherstate_nonce(const NoiseCipherState *state);

#ifdef __cplusplus
}
#endif
