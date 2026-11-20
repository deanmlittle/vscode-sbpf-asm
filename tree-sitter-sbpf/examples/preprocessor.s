.include "offsets.s"
.macro CHECK_SIGNER offset, err=err_signer
  ldxb r2, [r6 + \offset]
  jeq r2, 0, \err
.endm
.macro DEF_STR name, text
\name:
  .ascii \text
\name\()_end:
.endm
.macro LOOP
loop_\@:
.endm
.globl entrypoint
entrypoint:
  CHECK_SIGNER 0x9
.rept 4
  add64 r2, 1
.endr
.irp reg, r2, r3
  mov64 \reg, 0
.endr
1:
  sub64 r2, 1
  jne r2, 0, 1b   ; comment
  r1 += 5         // llvm dialect
  if r1 s>= r2 goto 1f
  *(u64 *)(r1 - 8) = r2
1: exit
.rodata
  message: .ascii "Hello, \"Solana\"!"
  quads: .quad 1, -2, message
