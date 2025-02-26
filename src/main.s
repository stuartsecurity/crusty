.extern init
.globl _start

.section ".text.prologue"

_start:
    push  rsi
    mov   rsi, rsp
    and   rsp, 0xFFFFFFFFFFFFFFF0
    sub   rsp, 0x20
    call  init
    mov   rsp, rsi
    pop   rsi
    ret
