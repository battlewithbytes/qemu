#!/usr/bin/env python3
"""Real qtest checks for cockpit-mmio and cockpit-shmem in patched QEMU."""
import mmap
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    binary = os.environ.get("COCKPIT_QEMU_BIN", "/opt/qemu/bin/qemu-system-aarch64")
    with tempfile.TemporaryDirectory(prefix="devices-") as directory:
        run = Path(directory)
        shared = run / "shared.bin"
        shared.write_bytes(bytes(4096))
        args = [binary, "-machine", "virt", "-cpu", "cortex-a72", "-m", "128",
                "-nic", "none", "-display", "none", "-serial", "none", "-monitor", "none", "-S",
                "-qtest", f"unix:{run}/qtest,server=on,wait=off", "-qtest-log", "/dev/null",
                "-d", "unimp", "-D", str(run / "mmio.log"),
                "-device", "cockpit-mmio,addr=0x10007000,size=4096,read-value=0x12345678",
                "-object", f"memory-backend-file,id=shared,mem-path={shared},size=4096,share=on",
                "-device", "cockpit-shmem,memdev=shared,addr=0x70000000"]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(5)
        try:
            for _ in range(100):
                if (run / "qtest").exists():
                    break
                if proc.poll() is not None:
                    raise AssertionError(proc.communicate()[1].decode())
                time.sleep(0.05)
            conn.connect(str(run / "qtest"))
            stream = conn.makefile("rwb", buffering=0)

            def command(text):
                stream.write((text + "\n").encode())
                reply = stream.readline().decode().strip()
                assert reply.startswith("OK"), reply
                return reply

            def read(addr, width="l"):
                return int(command(f"read{width} {addr}").split()[1], 16)

            assert read("0x10007024") == 0x12345678
            command("writel 0x10007024 0xffffffff")
            assert read("0x10007024") == 0x12345678, "constant backend unexpectedly latched a write"
            assert read("0x10007025", "b") == 0x56
            assert read("0x10008000") == 0xffffffff, "adjacent PCI aperture was overridden"
            with shared.open("r+b") as fh, mmap.mmap(fh.fileno(), 4096) as mapping:
                command("writel 0x70000000 0xaabbccdd")
                assert mapping[:4] == bytes.fromhex("ddccbbaa"), "guest-to-host visibility failed"
                mapping[4:8] = bytes.fromhex("78563412")
                assert read("0x70000004") == 0x12345678, "host-to-guest visibility failed"
            stream.close()
            print("PASS: exact MMIO reads/writes, adjacent PCI isolation, bidirectional shared bytes")
        finally:
            conn.close()
            proc.terminate()
            proc.communicate(timeout=10)
        trace = (run / "mmio.log").read_text()
        assert "cockpit-mmio read addr=0x10007024" in trace and "ignored" in trace
        # Both invalid zero-size and accidental RAM overlays fail before boot.
        for device in ("cockpit-mmio,addr=0x10007000,size=0", "cockpit-mmio,addr=0x40000000,size=4096"):
            result = subprocess.run(args[:args.index("-qtest")] + ["-device", device], capture_output=True, timeout=10)
            assert result.returncode != 0, "invalid mapping accepted"
        print("PASS: MMIO trace and invalid mapping rejection")


if __name__ == "__main__":
    main()
