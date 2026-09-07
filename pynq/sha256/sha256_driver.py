"""
PYNQ driver for the sha256_top IP
"""

from pynq import Overlay, MMIO, allocate
import time

# --- Register offsets, from xsha256_top_hw.h ---
REG_AP_CTRL   = 0x00   # bit0=ap_start, bit1=ap_done, bit2=ap_idle
REG_AP_RETURN = 0x10   # sha256_compute's return code (0 = ok, -1 = rejected)
REG_MSG_ADDR  = 0x18   # 64-bit pointer -> takes up 2 words (low, high)
REG_LEN       = 0x24
REG_HASH_ADDR = 0x2c   # 64-bit pointer -> takes up 2 words (low, high)

AP_START = 1 << 0
AP_DONE  = 1 << 1
AP_IDLE  = 1 << 2

SHA256_MAX_MESSAGE_BYTES = 256
SHA256_HASH_WORDS = 8


class Sha256Accel:
    def __init__(self, bitfile="sha256_bd_wrapper.bit"):
        self.overlay = Overlay(bitfile)

        # Adjust 'sha256_top_0' to the real IP block name in your design
        # (check overlay.ip_dict.keys() to confirm it)
        ip_info = self.overlay.ip_dict["sha256_top_0"]
        self.mmio = MMIO(ip_info["phys_addr"], ip_info["addr_range"])

        # Physical buffers shared with the IP (contiguous memory, required
        # so a 64-bit address can be used as a pointer by the hardware)
        self.msg_buf = allocate(shape=(SHA256_MAX_MESSAGE_BYTES,), dtype="u1")
        self.hash_buf = allocate(shape=(SHA256_HASH_WORDS,), dtype="u4")

    def _write_ptr(self, offset, physical_address):
        # 64-bit pointer split across two 32-bit registers
        self.mmio.write(offset, physical_address & 0xFFFFFFFF)
        self.mmio.write(offset + 4, (physical_address >> 32) & 0xFFFFFFFF)

    def compute(self, message: bytes) -> bytes:
        if len(message) > SHA256_MAX_MESSAGE_BYTES:
            raise ValueError(
                f"message of {len(message)} bytes exceeds the max "
                f"{SHA256_MAX_MESSAGE_BYTES} supported by the core"
            )

        # Load the message into the shared buffer
        self.msg_buf[: len(message)] = list(message)

        # Configure registers
        self.mmio.write(REG_LEN, len(message))
        self._write_ptr(REG_MSG_ADDR, self.msg_buf.physical_address)
        self._write_ptr(REG_HASH_ADDR, self.hash_buf.physical_address)

        # Start and wait for completion
        self.mmio.write(REG_AP_CTRL, AP_START)
        while not (self.mmio.read(REG_AP_CTRL) & AP_DONE):
            time.sleep(0.0001)

        # sha256_compute's return value: 0 = ok, -1 = message rejected
        # (the register is unsigned, so -1 reads back as 0xFFFFFFFF)
        rc_raw = self.mmio.read(REG_AP_RETURN)
        rc = rc_raw - (1 << 32) if rc_raw >= (1 << 31) else rc_raw
        if rc != 0:
            raise RuntimeError(f"sha256_compute returned {rc} (message rejected)")

        # The IP writes the hash into hash_buf directly (via m_axi)
        # Each SHA-256 word is big-endian by spec, but ARM is little-endian,
        # so the raw u32 values need a byteswap before turning into bytes
        return bytes(self.hash_buf.byteswap().tobytes())

    def close(self):
        self.msg_buf.close()
        self.hash_buf.close()


if __name__ == "__main__":
    accel = Sha256Accel("sha256_bd_wrapper.bit")

    message = bytes.fromhex("74ba2521")
    result = accel.compute(message)
    print(result.hex())
    # Expected (NIST CAVS Len=32): b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e

    accel.close()