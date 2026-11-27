/* Curve448 and NewHope are not built (unused by 2Link; Goldilocks needs GCC).
 * noise-c's dhstate.c still references their constructors, so these stubs
 * make any request for them fail cleanly with NOISE_ERROR_NO_MEMORY. */
#include "protocol/internal.h"

NoiseDHState *noise_curve448_new(void) { return 0; }
NoiseDHState *noise_newhope_new(void) { return 0; }
