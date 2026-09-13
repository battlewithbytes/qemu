#!/usr/bin/env python3
"""Bounded TCG/KVM instruction comparison; print facts, never a boot claim."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    binary = os.environ.get("COCKPIT_QEMU_BIN", "/opt/qemu/bin/qemu-system-aarch64")
    records = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(["aarch64-linux-gnu-as", "-o", str(root / "probe.o"),
                        str(Path(__file__).with_suffix(".S"))], check=True)
        subprocess.run(["aarch64-linux-gnu-ld", "-Ttext=0x40200000",
                        "-o", str(root / "probe.elf"), str(root / "probe.o")], check=True)
        subprocess.run(["aarch64-linux-gnu-objcopy", "-O", "binary", "--only-section=.text",
                        str(root / "probe.elf"), str(root / "probe.bin")], check=True)
        (root / "seed").write_bytes(bytes.fromhex("0300014d") + bytes(252))
        for accel, cpu in (("tcg", "cortex-a72"), ("kvm", "host")):
            endpoint = root / accel
            argv = [binary, "-machine", "virt", "-accel", accel, "-cpu", cpu, "-m", "128",
                "-nic", "none", "-display", "none", "-serial", "none", "-monitor", "none",
                "-device", f"loader,file={root}/probe.bin,addr=0x40200000,cpu-num=0,force-raw=on",
                "-device", f"cockpit-sspm-mailbox,analysis=on,ram-size=4096,addr=0x10450000,ctrl-addr=0x10451000,boot-layout={root}/seed",
                "-qtest", f"unix:{endpoint},server=on,wait=off", "-qtest-log", "/dev/null"]
            proc = subprocess.Popen(argv, stderr=subprocess.PIPE)
            conn = socket.socket(socket.AF_UNIX)
            conn.settimeout(2)
            try:
                for _ in range(100):
                    if endpoint.exists():
                        break
                    if proc.poll() is not None:
                        raise AssertionError(proc.communicate()[1].decode())
                    time.sleep(.02)
                conn.connect(str(endpoint))
                with conn.makefile("rwb", buffering=0) as stream:
                    def read(offset):
                        stream.write(f"readl {0x40202000 + offset:#x}\n".encode())
                        reply = stream.readline().decode().split()
                        assert reply[0] == "OK", reply
                        return int(reply[1], 16)
                    for _ in range(100):
                        if read(0):
                            break
                        time.sleep(.02)
                    record = dict(accel=accel, status=read(0), simple_load=hex(read(4)),
                                  postindex_load=hex(read(8)), esr=hex(read(16)),
                                  fault_pc=hex(read(24)))
                    assert record["status"] == 1, record
                    assert record["simple_load"] == "0x4d010003", record
                    assert record["postindex_load"] == "0x4d010003", record
                    records.append(record)
            finally:
                conn.close()
                proc.terminate()
                _, error = proc.communicate(timeout=5)
                if proc.returncode not in (0, -15):
                    print(error.decode(errors="replace"), flush=True)
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
