#include "sha256_top.h"

int sha256_top(const u8 msg[SHA256_MAX_MESSAGE_BYTES], u32 len, u32 hash[SHA256_HASH_WORDS])
{
    // Control/status registers (start, done, return value, len) all live in
    // one AXI-Lite bundle so the ARM side drives the core through a single
    // memory-mapped register block.
#pragma HLS INTERFACE s_axilite port=return bundle=CTRL
#pragma HLS INTERFACE s_axilite port=len    bundle=CTRL
#pragma HLS INTERFACE s_axilite port=msg    bundle=CTRL
#pragma HLS INTERFACE s_axilite port=hash   bundle=CTRL

    // msg and hash are bulk data, so they go over AXI4 master ports instead
    // of AXI-Lite registers. offset=slave lets Vivado wire these to any
    // address (e.g. a PYNQ-allocated buffer) rather than a fixed address.
    // depth is required for csim/cosim since HLS can't infer an array bound
    // from a bare pointer.
#pragma HLS INTERFACE m_axi port=msg  offset=slave bundle=DATA depth=SHA256_MAX_MESSAGE_BYTES
#pragma HLS INTERFACE m_axi port=hash offset=slave bundle=DATA depth=SHA256_HASH_WORDS

    u32 local_hash[SHA256_HASH_WORDS];

    // The validated core is called unmodified; size_t vs u32 for len is the
    // only adaptation needed since HLS interface ports prefer fixed-width
    // types over size_t.
    int rc = sha256_compute(msg, static_cast<size_t>(len), local_hash);

    for (int i = 0; i < SHA256_HASH_WORDS; i++)
        hash[i] = local_hash[i];

    return rc;
}