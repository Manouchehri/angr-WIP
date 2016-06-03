
# coding: utf-8

# In[ ]:

import angr


# In[ ]:

fail = (0x400947, 0x400958)
win  = (0x400936,)
main = 0x400886

# GDB infos
# stack_begin = 0x7ffffffde000
# stack_end   = 0x7ffffffff000
# heap_begin  = 0x602000
# heap_end    = 0x623000
# breakpoint  = 0x400909

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

def get_length(state):
    global flag_addr
    flag_addr = state.regs.rax
    print(flag_addr)
    state.regs.rsi = 8
    
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


# In[ ]:

p = angr.Project('r200.bin')
p.hook(0x400914, func=get_length, length=5)


# In[ ]:

init = p.factory.blank_state(addr=main)

# init.gdb.set_stack('assets/stack', stack_top=0x7ffffffde000)
# print("Stack set")

# init.gdb.set_heap('assets/heap', heap_base=0x602000)
# print("Heap set") 

# # https://github.com/angr/simuvex/blob/efa097d4076401cbd48277223e1340d7c6dffbc1/simuvex/plugins/gdb.py#L97
# # Some registers such as cs, ds, eflags etc. aren't supported in Angr
# init.gdb.set_regs('assets/regs')
# print("Registers set")


# In[ ]:

pgp = p.factory.path_group(init, threads=8)


# In[ ]:

ex = pgp.explore(find=win, avoid=fail)
print_paths(ex, trace=True)
print(ex)


# In[ ]:



