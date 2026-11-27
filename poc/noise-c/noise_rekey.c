#include "noise_rekey.h"

#include <sodium.h>

#include "protocol/internal.h"

int poc_noise_cipherstate_rekey(NoiseCipherState *state)
{
    uint8_t block[32 + 16];
    uint64_t saved_n;
    int err;

    if (!state)
        return NOISE_ERROR_INVALID_PARAM;
    if (!state->has_key)
        return NOISE_ERROR_INVALID_STATE;
    if (state->key_len != 32 || state->mac_len > 16)
        return NOISE_ERROR_NOT_APPLICABLE;

    sodium_memzero(block, sizeof(block));
    saved_n = state->n;
    state->n = 0xFFFFFFFFFFFFFFFFULL;              /* maxnonce, reserved for Rekey */
    err = (*(state->encrypt))(state, NULL, 0, block, 32);
    state->n = saved_n;                            /* counter is not changed */
    if (err == NOISE_ERROR_NONE)
        (*(state->init_key))(state, block);        /* backend hook: does not reset n */
    sodium_memzero(block, sizeof(block));
    return err;
}

uint64_t poc_noise_cipherstate_nonce(const NoiseCipherState *state)
{
    return state ? state->n : 0;
}
