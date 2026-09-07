import time
from sha256_driver import Sha256Accel

# Same vectors as test_sha256_top.cpp (NIST CAVS "SHA-256 ShortMsg")
TEST_VECTORS = [
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("d3", "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1"),
    ("11af", "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98"),
    ("74ba2521", "b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e"),
    ("5738c929c4f4ccb6", "963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf"),
    ("0a27847cdc98bd6f62220b046edd762b", "80c25ec1600587e7f28b18b1b18e3cdc89928e39cab3bc25e4d4a4c139bcedc4"),
    ("09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95", "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"),
    ("5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509", "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa"),
]


def main():
    accel = Sha256Accel("sha256_bd_wrapper.bit")

    total = 0
    passed = 0
    durations = []

    for message_hex, expected_hex in TEST_VECTORS:
        total += 1
        msg_bytes = bytes.fromhex(message_hex)

        start = time.perf_counter()
        result = accel.compute(msg_bytes)
        durations.append(time.perf_counter() - start)

        got_hex = result.hex()
        ok = (got_hex == expected_hex)

        label = f"len={len(msg_bytes)}B"
        status = "OK" if ok else "FAIL"
        print(f"[{status}] {label}  hash={got_hex}")
        if not ok:
            print(f"       expected: {expected_hex}")

        if ok:
            passed += 1

    # Oversized message: rejected (rc = -1)
    total += 1
    try:
        accel.compute(bytes(256))
        overflow_ok = False
    except RuntimeError:
        overflow_ok = True
    print(f"[{'OK' if overflow_ok else 'FAIL'}] oversized input rejected cleanly")
    if overflow_ok:
        passed += 1

    accel.close()

    print()
    print(f"{passed}/{total} passed")

    def stats(label, durations):
        avg_ms = sum(durations) / len(durations) * 1e3
        min_ms = min(durations) * 1e3
        max_ms = max(durations) * 1e3
        print(f"{label} latency: avg={avg_ms:.3f} ms  min={min_ms:.3f} ms  max={max_ms:.3f} ms")

    if durations:
        stats("compute", durations)


if __name__ == "__main__":
    main()