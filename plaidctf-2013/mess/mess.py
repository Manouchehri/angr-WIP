
# coding: utf-8

# In[1]:

import simuvex
import angr


# In[2]:

# PlaidCTF 2013 - mess
# @author: P1kachu <p1kachu@lse.epita.fr>


# In[3]:

path_types = [ 
    #'avoid',
    'errored',
    'deadended',
    'found',
    #'pruned',
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
    
def get_addr(state):
        global flag_addr
        flag_addr = state.regs.eax
        print(state.regs.eax)


# In[4]:

BINARY = 'mess.bin'
fail = (0x8048CC3, 0x8048CFF)
win  = (0x8048dfe)
main = 0x8048D10
flag_addr = -1

PASS_LEN = 29 # From 0x080487d8


# In[5]:

p = angr.Project(BINARY)
# p.hook(0x08048d10 + 0x82, func=get_length, length=3)
p.hook(0x80487e7, func=get_addr, length=3)


# In[6]:

init = p.factory.blank_state(addr=main)


# In[7]:

pgp = p.factory.path_group(init)


# In[8]:

ex = pgp.explore(find=win, avoid=fail)
print(ex)


# In[9]:

# print_paths(ex, trace=True)
p = ex.found[0]
print("Flag address: {0}".format(flag_addr))


# In[10]:

print(p.state.memory.load(flag_addr, PASS_LEN))


# In[ ]:



