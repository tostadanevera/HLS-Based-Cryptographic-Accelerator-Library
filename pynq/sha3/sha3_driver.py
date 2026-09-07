"""
PYNQ driver for the sha3_top IP
"""

from pynq import Overlay, MMIO, allocate
import time

# --- Register offsets, derived from xsha3_top_hw.h / ---
REG_AP_CTRL   = 0x00   # bit0=ap_start, bit1=ap_done, bit2=ap_idle
REG_AP_RETURN = 0x10   # sha3_256_compute's return code (0 = ok, -1 = rejected)
REG_MSG_ADDR  = 0x18   # 64-bit pointer -> takes up 2 words (low, high)
REG_LEN       = 0x24
REG_HASH_ADDR = 0x2c   # 64-bit pointer -> takes up 2 words (low, high)

AP_START = 1 << 0
AP_DONE  = 1 << 1
AP_IDLE  = 1 << 2

SHA3_MAX_MESSAGE_BYTES = 256
SHA3_256_HASH_BYTES = 32


class Sha3Accel:
    def __init__(self, bitfile="sha3_bd_wrapper.bit"):
        self.overlay = Overlay(bitfile)

        ip_info = self.overlay.ip_dict["sha3_top_0"]
        self.mmio = MMIO(ip_info["phys_addr"], ip_info["addr_range"])

        # Physical buffers shared with the IP
        self.msg_buf = allocate(shape=(SHA3_MAX_MESSAGE_BYTES,), dtype="u1")
        self.hash_buf = allocate(shape=(SHA3_256_HASH_BYTES,), dtype="u1")

    def _write_ptr(self, offset, physical_address):
        # 64-bit pointer split across two 32-bit registers
        self.mmio.write(offset, physical_address & 0xFFFFFFFF)
        self.mmio.write(offset + 4, (physical_address >> 32) & 0xFFFFFFFF)

    def compute(self, message: bytes) -> bytes:
        if len(message) > SHA3_MAX_MESSAGE_BYTES:
            raise ValueError(
                f"message of {len(message)} bytes exceeds the max "
                f"{SHA3_MAX_MESSAGE_BYTES} supported by the core"
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

        # sha3_256_compute's return value: 0 = ok, -1 = message rejected
        # (the register is unsigned, -1 = 0xFFFFFFFF)
        rc_raw = self.mmio.read(REG_AP_RETURN)
        rc = rc_raw - (1 << 32) if rc_raw >= (1 << 31) else rc_raw
        if rc != 0:
            raise RuntimeError(f"sha3_256_compute returned {rc} (message rejected)")

        # hash_o is a raw u8[32] array computed byte-wise in software, so
        # no endianness conversion is needed here (unlike SHA-256's u32[8]
        # word output, which needed a byteswap in sha256_driver.py)
        return bytes(self.hash_buf.tobytes())

    def close(self):
        self.msg_buf.close()
        self.hash_buf.close()


if __name__ == "__main__":
    accel = Sha3Accel("sha3_bd_wrapper.bit")

    result = accel.compute(b"")
    print(result.hex())
    # Expected (NIST CAVS Len=0): a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a

    accel.close()