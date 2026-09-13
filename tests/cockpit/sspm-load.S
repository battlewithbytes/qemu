/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Execute the driver's post-indexed MMIO load, not just a qtest transaction. */
.text
.global _start
_start:
    adr x9, vectors
    msr vbar_el1, x9
    isb
    mov x1, #0x10450000
    adr x3, results
    ldr w0, [x1]
    str w0, [x3, #4]
    ldr w2, [x1], #4
    str w2, [x3, #8]
    mov w0, #1
    str w0, [x3]
halt:
    wfi
    b halt
exception:
    adr x3, results
    mrs x0, esr_el1
    str x0, [x3, #16]
    mrs x0, elr_el1
    str x0, [x3, #24]
    mov w0, #2
    str w0, [x3]
    b halt
.org 0x1000
vectors:
.rept 16
    b exception
    .balign 128
.endr
.org 0x2000
results:
    .space 32
