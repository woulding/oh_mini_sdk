
.section .jumper.init.text, "ax"
.globl __init_booting_jump
.type __init_booting_jump, %function
__init_booting_jump:
    tail _start