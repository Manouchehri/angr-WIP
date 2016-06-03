
# coding: utf-8

# In[ ]:

import simuvex
import angr


# In[ ]:

# Hacklu 2013 - reverse_me
# @author: P1kachu <p1kachu@lse.epita.fr>


# In[ ]:

path_types = [ 
    'avoid',
    'errored',
    'pruned',
    'stashed',
    'unconstrained',
    'unsat'
]
def print_paths(ex, trace=False):
    for p_type in path_types:
        for path in getattr(ex, p_type):
            print(path)
            if p_type == 'errored':
                print(path.error)
            if trace:
                for step in path.trace:
                    print(step)

def i_am_clean(state):
    print("I am clean at {0}".format(state.regs.eip))
    state.regs.eax = 0

def return_first_arg(state):
    print("Hooked at {0}".format(state.regs.eip))
    state.regs.eax = state.memory.load(state.regs.esp, 8)


# In[ ]:

BINARY = 'reverse_me.bin'
fail = (0x08048e18, 0x08048711)
win  = (0x08048e0a)
main = 0x080486f7
flag_addr = 0xd0000010

# Need something symbolic, we don't have the length !
PASS_LEN = 20

# IDA Xrefs
patch_me_rel = [0x2a, 0x2ed, 0x42, 0x103, 0x16b, 0x1f2, 0x3c4, 0x71a, 0x728, 0xf7, 0x1e6, 0x3b8]
patch_me_abs = [0x0804866a, 0x080486c0]
patch_malloc = [0x66, 0x158, 0x216]
patch_strlen = [0x5e, 0xaa, 0xe2, 0x150, 0x1d1, 0x20e, 0x258, 0x36a, 0x39f]


# In[ ]:

p = angr.Project('binaries/{}'.format(BINARY))

# Sleeps
for x in patch_me_abs:
    p.hook(x, func=return_first_arg, length=5)

# Sleeps, puts, printfs
for x in patch_me_rel:
    p.hook(main + x, func=return_first_arg, length=5)
    
for x in patch_malloc:
    p.hook(main + x, simuvex.SimProcedures['libc.so.6']['malloc'])
    
for x in patch_strlen:
    p.hook(main + x, simuvex.SimProcedures['libc.so.6']['strlen'])
    
p.hook(main + 0xf, func=i_am_clean, length=5)


# In[ ]:

init = p.factory.blank_state(addr=main)
argv=[BINARY, init.se.BVS('arg1', PASS_LEN * 8)]

init.memory.store(0xd0000000, argv[0])
init.memory.store(flag_addr, argv[1])
init.stack_push(flag_addr)
init.stack_push(0xd0000000)
init.stack_push(init.regs.esp) # argv
init.stack_push(2) # argc
init.stack_push(main) # argc


# In[ ]:

pgp = p.factory.path_group(init)


# In[ ]:

ex = pgp.explore(find=win, avoid=fail)
print(ex)


# In[ ]:

print_paths(ex, trace=True)

