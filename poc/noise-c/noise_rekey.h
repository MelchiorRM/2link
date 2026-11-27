#pragma once

#include <noise/protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Noise spec §4.2 / §11.3 Rekey():
 *   k' = first 32 bytes of ENCRYPT(k, n = 2^64 - 1, ad = empty, plaintext = 32 zero bytes)
 * The nonce counter n is left unchanged. noise-c has no Rekey(), so this shim
 * uses noise-c's internal CipherState hooks.
 *
 * Returns NOISE_ERROR_NONE, NOISE_ERROR_INVALID_PARAM, NOISE_ERROR_INVALID_STATE
 * (no key) or NOISE_ERROR_NOT_APPLICABLE (key length is not 32 bytes). */
int poc_noise_cipherstate_rekey(NoiseCipherState *state);

/* Test helper: current nonce counter (noise-c has no getter). */
uint64_t poc_noise_cipherstate_nonce(const NoiseCipherState *state);

#ifdef __cplusplus
}
#endif
