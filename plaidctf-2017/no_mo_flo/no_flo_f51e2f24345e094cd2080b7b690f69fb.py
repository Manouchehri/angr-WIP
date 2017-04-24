# PlaidCTF 2017
# no_mo_flo - Reversing
# LSE - p1kachu@lse.epita.fr - gabriel@lse.epita.fr

import angr
from simuvex.procedures.stubs.UserHook import UserHook

p = angr.Project('no_flo_f51e2f24345e094cd2080b7b690f69fb.bin')

# Blocks to avoid in both functions
avoid = (0x4027f8, 0x40071d, 0x40077a, 0x4007d7, 0x400834, 0x400894, 0x4008f4,
0x400950, 0x4009a8, 0x400a09, 0x400a6f, 0x400ac7, 0x400b24, 0x400b81, 0x400bd9,
0x400c31, 0x400c8e, 0x400ce6, 0x400d3e, 0x400d96, 0x400df2, 0x400e4a, 0x400ea0,
0x400eeb, 0x400fb3, 0x4010ba, 0x4011bc, 0x4012be, 0x4013c6, 0x4014d4, 0x4015d6,
0x4016c0, 0x4017c2, 0x4018c4, 0x4019cd, 0x401ab7, 0x401bb9, 0x401cc5, 0x401db2,
0x401eba, 0x401fbc, 0x4020c2, 0x4021c4, 0x4022cb, 0x4023ba, 0x4024bc, 0x4025c3,
0x4026b2)

# Jumps emulation
hooks = (0x400f52, 0x400fc7, 0x401059, 0x4010ce, 0x40115b, 0x4011d0, 0x40125d,
0x4012d2, 0x401365, 0x4013da, 0x401473, 0x4014e8, 0x401575, 0x4015ea, 0x40165f,
0x4016d4, 0x401761, 0x4017d6, 0x401863, 0x4018d8, 0x40196c, 0x4019e1, 0x401a56,
0x401acb, 0x401b58, 0x401bcd, 0x401c64, 0x401cd9, 0x401d51, 0x401dc6, 0x401e59,
0x401ece, 0x401f5b, 0x401fd0, 0x402061, 0x4020d6, 0x402163, 0x4021d8, 0x40226a,
0x4022df, 0x402359, 0x4023ce, 0x40245b, 0x4024d0, 0x402562, 0x4025d7, 0x402651,
0x4026c6)

find = 0x4027ec
main = 0x40272e
flag_addr = 0

def read(state):
    state.regs.rax = 32
    global flag_addr
    flag_addr = state.regs.rsi
    for i in range(31):
        if i % 2 == 0:
            state.mem[state.regs.rsi + i].char = state.se.BVS('c', 8)
    state.mem[state.regs.rsi + 31].char = '}'
    state.add_constraints(state.memory.load(state.regs.rsi, 5) == int("PCTF{".encode("hex"), 16))

def do_nothing(state):
    pass

p.hook(0x4027ba, angr.Hook(UserHook, user_func=do_nothing, length=5))
p.hook(0x40274a, angr.Hook(UserHook, user_func=read, length=5))

CF = 1
PF = 4
AF = 0x10
ZF = 0x40
SF = 0x80
OF = 0x800

BATARD_JNL = 1
BATARD_JNG = 2
BATARD_JG = 3
BATARD_JL = 4
BATARD_JNE = 5
BATARD_JE = 6
BATARD_JMP = 7

batard_ops = {
    BATARD_JNL: lambda e: (e & SF) == (e & OF),
    BATARD_JNG: lambda e: ((e & ZF) == 1) or ((e & SF) != (e & OF)),
    BATARD_JG: lambda e: ((e & ZF) == 0) and ((e & SF) == (e & OF)),
    BATARD_JL: lambda e: ((e & SF) != (e & OF)),
    BATARD_JNE: lambda e: ((e & ZF) == 0),
    BATARD_JE: lambda e: ((e & ZF) == 1),
    BATARD_JMP: lambda e: True,
}

def batard_op(state):
    rflags = state.regs.rflags # WE NEED rflags HERE
    op = state.se.eval(state.regs.r11, 1)[0]
    if batard_ops[op](state.se.eval(state.regs.rflags, 1)[0]):
        state.regs.rip = state.regs.r10

block_size = 0x400fb3 - 0x400f52

for hook in hooks:
    p.hook(hook, angr.Hook(UserHook, user_func=batard_op, length=block_size))

init = p.factory.blank_state(addr=main)
pgp = p.factory.path_group(init)
ex = pgp.explore(find=find, avoid=avoid)


print(ex)
print(ex.found[0].state.se.any_str(ex.found[0].state.memory.load(flag_addr, 100)))

