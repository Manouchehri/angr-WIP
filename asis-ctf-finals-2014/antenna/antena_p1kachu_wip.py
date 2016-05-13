import angr
import simuvex
import logging

"""
ANTENNA - ASISCTF Finals 2014 - Antenna
WIP
@author: P1kachu
"""

win            = 0x400fe3  # Prints "good try"
fail           = 0x400f9b  # Prints "sorry"
check_flag     = 0x400c65  # Beginning of function that checks the flag
check_flag_end = 0x400cf1  # First instruction of last basic block of function that checks the flag
call_check     = 0x400fd2  # Addgress of the 'call check_flag' instruction
main           = 0x400e53  # Address of main
ret            = 0x400fd7  # Last instruction of check_flag function
expected       = 0x9ddf44  # Expected value
PASS_LEN       = 152
find           = (win,)
avoid          = (fail,)


def hook_strlen(state):
    state.regs.rax = PASS_LEN
def hook_gmpz_strlen(state):
    state.regs.rax = 200

def hook_fgets_printf(state):
    return
#     Useless here finally
#     state.mem[0x2000:] = state.se.BVS('pass', PASS_LEN * 8)

#     for i in xrange(PASS_LEN):
#         char = state.memory.load(0x2000 + i, 1)
#         state.add_constraints(char >= ord('0'))
#         state.add_constraints(char <= ord('9'))

#     state.regs.rax = 0x2000

def hook_gmpz(state):

    LEN = 0x200 # Completely arbitrary, don't know how to guess it

    state.mem[0x2000:] = state.se.BVS('pass', LEN * 8)

    for i in xrange(PASS_LEN):
        char = state.memory.load(0x2000 + i, 1)
        state.add_constraints(char >= ord('0'))
        state.add_constraints(char <= ord('1'))

    state.regs.rax = 0x2000


# def hook_retval(state):
    # We want to constraint rax only at
    # a specific address
    # state.regs.rax = state.mem[state.regs.rbp - 0xc]
    # state.add_constraints(state.regs.rax == expected)


# use_sim_procedure - Whether to replace resolved
#                     dependencies for which
#                     simprocedures are available
#                     with said simprocedures.
# p = angr.Project('antena', use_sim_procedures=True)
# p = angr.Project('antena', load_options={"auto_load_libs": False})
p = angr.Project('antena')


# Lazy solves: LAZY_SOLVES should be disabled
#              sometimes to avoid creating too
#              many paths.

#init = p.factory.blank_state(addr=main, remove_options={simuvex.s_options.LAZY_SOLVES})
init = p.factory.blank_state(addr=main)

# Patch fgets and printf
p.hook(0x400f3f, func=hook_fgets_printf, length=(0x400f69 - 0x400f3f))

# Patch gmpz
p.hook(0x400faf, func=hook_gmpz, length=(0x400fd2 - 0x400faf))

# Hook strlen
p.hook(0x400f2c, func=hook_strlen, length=5)
p.hook(0x400f73, func=hook_strlen, length=5)
p.hook(0x400f8e, func=hook_strlen, length=5)
p.hook(0x400c7f, func=hook_gmpz_strlen, length=5)

#p.hook(check_flag_end, func=hook_retval, length=3)



pgp = p.factory.path_group(init, threads=8)
x = pgp.explore(find=find, avoid=avoid)
print(x)
