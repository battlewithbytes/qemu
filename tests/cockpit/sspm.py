#!/usr/bin/env python3
"""Real qtest: mailbox storage, no fabricated reply, reset and rejection."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    binary = os.environ.get("COCKPIT_QEMU_BIN", "/opt/qemu/bin/qemu-system-aarch64")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        seed = root / "seed.bin"
        seed.write_bytes(bytes.fromhex("0300014d") + bytes(252))
        prefix = [binary, "-machine", "virt", "-cpu", "cortex-a72", "-m", "128",
                  "-nic", "none", "-display", "none", "-serial", "none", "-monitor", "none", "-S"]
        device = f"cockpit-sspm-mailbox,analysis=on,addr=0x10450000,ctrl-addr=0x10451000,boot-layout={seed}"
        second = "cockpit-sspm-mailbox,analysis=on,addr=0x10460000,ctrl-addr=0x10461000"
        proc = subprocess.Popen(prefix + ["-device", device, "-device", second, "-qtest",
            f"unix:{root}/qtest,server=on,wait=off", "-qtest-log", "/dev/null",
            "-qmp", f"unix:{root}/qmp,server=on,wait=off"], stderr=subprocess.PIPE)
        conn, qmp = socket.socket(socket.AF_UNIX), socket.socket(socket.AF_UNIX)
        conn.settimeout(5)
        qmp.settimeout(5)
        try:
            for _ in range(100):
                if (root / "qtest").exists():
                    break
                if proc.poll() is not None:
                    raise AssertionError(proc.communicate()[1].decode())
                time.sleep(.05)
            conn.connect(str(root / "qtest"))
            qmp.connect(str(root / "qmp"))
            with conn.makefile("rwb", buffering=0) as stream, qmp.makefile("rwb", buffering=0) as monitor:
                def cmd(line):
                    stream.write((line + "\n").encode())
                    reply = stream.readline().decode().strip()
                    assert reply.startswith("OK"), reply
                    return reply

                def read(address):
                    return int(cmd(f"readl {address:#x}").split()[1], 16)

                def qcmd(name):
                    monitor.write((json.dumps({"execute": name}) + "\n").encode())
                    while True:
                        result = json.loads(monitor.readline())
                        if "return" in result or "error" in result:
                            assert "error" not in result, result
                            return

                assert "QMP" in json.loads(monitor.readline())
                qcmd("qmp_capabilities")
                assert read(0x10450000) == 0x4d010003
                assert read(0x10460000) == 0
                cmd("writel 0x10460000 0x12345678")
                cmd("writeb 0x10450001 0xab")
                assert read(0x10450000) == 0x4d01ab03
                cmd("writel 0x104500fc 0xdeadbeef")
                assert read(0x104500fc) == 0xdeadbeef
                cmd("writel 0x10451000 0x2")
                cmd("writel 0x10451000 0x4")
                assert read(0x10451000) == 6
                assert read(0x10461000) == 0, "doorbell leaked into another bank"
                assert read(0x10460000) == 0x12345678
                assert read(0x10451004) == 0, "fabricated receive completion"
                cmd("writel 0x10451004 0xffffffff")
                assert read(0x10451004) == 0
                assert read(0x10450100) == 0xffffffff, "overmapped bank"
                qcmd("system_reset")
                # QMP acknowledges the reset request before the main loop
                # necessarily performs it; wait for the observable state.
                for _ in range(100):
                    if read(0x10450000) == 0x4d010003:
                        break
                    time.sleep(.01)
                assert read(0x10450000) == 0x4d010003
                assert read(0x104500fc) == 0
                assert read(0x10451000) == 0
                assert read(0x10460000) == 0
        finally:
            conn.close()
            qmp.close()
            proc.terminate()
            proc.communicate(timeout=10)
        for invalid in (device.replace("analysis=on", "analysis=off"),
                        device.replace("addr=0x10450000", "addr=0x40000000"),
                        device.replace("ctrl-addr=0x10451000", "ctrl-addr=0x10450004"),
                        device + ",addr=0x10450001",
                        device.replace(str(seed), str(root / "missing"))):
            result = subprocess.run(prefix + ["-device", invalid], capture_output=True, timeout=5)
            assert result.returncode != 0, invalid
        result = subprocess.run(prefix + ["-device", device, "-device", device], capture_output=True, timeout=5)
        assert result.returncode != 0, "overlapping devices accepted"
        seed.write_bytes(b"short")
        assert subprocess.run(prefix + ["-device", device], capture_output=True, timeout=5).returncode != 0
    print("PASS: SSPM bank storage, partial access, doorbell/no reply, reset, isolation, seven refusals")


if __name__ == "__main__":
    main()
