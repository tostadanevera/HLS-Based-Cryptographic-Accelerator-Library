# HLS-Based Cryptographic Accelerator Library for FPGA

> **Research and educational use only.** The accelerators in this
> repository were built to characterize and compare HLS-based cryptographic
> hardware, not to serve as production-ready cryptographic implementations.
> They have **not** undergone the side-channel analysis, constant-time
> hardening, or independent security review that any real-world
> cryptographic deployment requires.
> **Do not use this code to protect real data or in any
> production system.**

Characterization and comparative analysis of five cryptographic hardware
accelerators (**AES-128**, **Serpent**, **ChaCha20**, **SHA-256**, and
**SHA3-256**) implemented with High-Level Synthesis (Vitis HLS) and deployed
on a **PYNQ-Z2** board (Zynq-7020, `xc7z020clg400-1`).

## Repository structure

```
crypto_lib/
|-- common/
|   `-- types.h                        # shared type aliases (u8, u32, u64)
|-- aes/
|   |-- aes.h, aes.cpp                 # core
|   |-- test_aes.cpp                   # KAT testbench
|   `-- hls/
|       |-- aes_top.h, aes_top.cpp     # AXI wrapper
|       |-- test_aes_top.cpp           # HLS wrapper testbench
|       `-- hls_config.cfg             # Vitis HLS project config
|-- serpent/                           # same structure as aes/
|-- chacha20/                          # same structure as aes/
|-- sha256/                            # same structure as aes/
|-- sha3/                              # same structure as aes/
|-- modes/
|   |-- modes.h, modes.cpp             # generic block_op_fn ECB/CBC/CTR layer
|   `-- test_modes.cpp
|-- drivers/                           # PYNQ Python drivers and *_verify.py scripts
|-- hls/                               # config files
|-- vivado/                            # final .bit/.hwh, config files
`-- Makefile
```

## Building and running the software testbenches

```bash
make test          # builds and runs all 5 software testbenches
make test-aes      # builds and runs a single algorithm's testbench
make clean
```

## Deploying to the PYNQ-Z2

1. Copy the algorithm's `.bit` and matching `.hwh` (same base filename, same
   directory) to the board.
2. Run the corresponding driver from `drivers/`.
3. Each algorithm also has a `*_verify.py` script that re-runs its test vectors
   directly on hardware.

## Rebuilding the hardware from source (optional)

The `.bit`/`.hwh` pairs under `/vivado/` are ready to
deploy directly, as above, rebuilding an accelerator's hardware from source
is **not required** for deploying to the PYNQ-Z2. The steps below are
kept for completeness, in case the design ever needs to be resynthesized,
modified, or ported to a different board.

### Step 1 — Run Vitis HLS synthesis

```bash
cd aes/hls
v++ --mode hls --config hls_config.cfg
```

This regenerates the algorithm's `*_hls/` working directory, which is not
tracked in this repository since it is large and fully reproducible from
this one command.

### Step 2 — Locate and commit the packaged IP

Inside the generated directory, look for a subfolder ending
in `hls/impl/ip/`, this is the packaged IP.
Copy it into this repository's `vivado/ip/aes128_top/`.

### Step 3 — Reconstruct the Vivado project

```bash
cd vivado
vivado -mode batch -source build_aes_project.tcl
```

This recreates the block design (Zynq Processing System + SmartConnect for
AXI-Lite control + AXI Interconnect for AXI4 data over HP0), reading the IP
from `vivado/ip/`.

### Step 4 — Export the final bitstream

Once `Generate Bitstream` completes inside the reconstructed project, copy
the resulting `.bit` and its matching `.hwh` to the board.

## Requirements

- Vitis HLS 2023.2+ and Vivado (same version), targeting `xc7z020clg400-1`
- PYNQ image on the target board, with the `pynq` Python package
- A C++17 compiler for the software testbenches