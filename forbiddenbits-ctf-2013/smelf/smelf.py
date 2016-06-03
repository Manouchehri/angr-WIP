
# coding: utf-8

# In[ ]:

import simuvex
import angr


# In[ ]:

# Forbidden Bits CTF 2013 - smelf
# @author: P1kachu <p1kachu@lse.epita.fr>


# In[ ]:

fail = (0x400623, 0x4006b5)
win  = (0x4006f0)
main = 0x400601
flag_addr = 0xd0000010
PASS_LEN = 29


# In[ ]:

p = angr.Project('smelf.bin')


# In[ ]:

init = p.factory.blank_state(addr=main)
argv=['smelf.bin', init.se.BVS('arg1', PASS_LEN * 8)]

# for i in xrange(PASS_LEN):
#     init.add_constraints(argv[1].get_byte(i) >= 0x20)
#     init.add_constraints(argv[1].get_byte(i) <= 0x7f)
# init.add_constraints(argv[1].get_byte(PASS_LEN) == 0)
    
init.memory.store(0xd0000000, argv[0])
init.memory.store(flag_addr, argv[1])
init.regs.rdi = 0xd0000010
init.regs.rsi = 0xd0000000
    
def fast_strlen(state):
    state.regs.rax = 29


# In[ ]:

pgp = p.factory.path_group(init)
p.hook(addr=0x400618, func=fast_strlen, length=5)
p.hook(addr=0x4006e2, func=fast_strlen, length=5)


# In[ ]:

ex = pgp.explore(find=win, avoid=fail)
print(ex)


# In[ ]:

state = ex.found[0].state

# INVALID FLAG...
# Writeup for this exercice can be found there:
# https://scoding.de/forbiddenbits-ctf-2013-smelf
print(state.se.any_str(state.memory.load(flag_addr, PASS_LEN)))


# In[ ]:



