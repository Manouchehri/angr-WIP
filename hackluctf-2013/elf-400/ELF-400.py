
# coding: utf-8

# In[1]:

import simuvex
import angr


# In[2]:

# Hacklu 2013 - reverse_me 400
# @author: P1kachu <p1kachu@lse.epita.fr>


# In[3]:

path_types = [ 
    'avoid',
    'errored',
    'deadended',
    'found',
    'pruned',
    'stashed',
    'unconstrained',
    'unsat'
]

def print_paths(ex, trace=False):
    for p_type in path_types:
        for path in getattr(ex, p_type):
            print("")
            print("{0}: {1}".format(p_type, path))
            if p_type == 'errored':
                print("Error: {0}".format(path.error))
            if trace:
                for step in path.trace:
                    print(step)

def i_am_clean(state):
    # Bypass ptrace/ld_peload checks
    state.regs.eax = 0


# In[4]:

BINARY = 'reverse_me.bin'
fail = (0x08048e18, 0x08048711)
win  = (0x08048e16)
main = 0x080486f7
flag_addr = 0xd0000010
argv_addr = 0xd0000000

# Need something symbolic, we don't have the length
PASS_LEN = 100


# In[5]:

p = angr.Project(BINARY)
p.hook(main + 0xf, func=i_am_clean, length=5)


# In[6]:

init = p.factory.blank_state(addr=main)
argv=[BINARY, init.se.BVS('arg1', PASS_LEN * 8)]

init.memory.store(argv_addr, argv[0])
init.memory.store(flag_addr, argv[1])
init.regs.edi = argv_addr 
init.regs.esi = 2 # argc


# In[7]:

pgp = p.factory.path_group(init)


# In[8]:

ex = pgp.explore(find=win, avoid=fail)
print(ex)


# In[9]:

#print_paths(ex, trace=True)


# In[10]:

s = ex.found[0].state
tmp = s.memory.load(flag_addr, PASS_LEN)


# In[ ]:



