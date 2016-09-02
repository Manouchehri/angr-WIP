
# coding: utf-8

# In[ ]:

import angr
import re
# DCTF - r200
# @author: P1kachu


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
    'avoid',
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

def parse_regs(regs_dump):
    reg = re.compile(r'[\S]*')
    val = re.compile(r'0x[\w]*')
    registers = {}
    with open(regs_dump, 'r') as f:
        lines = f.readlines()
        for line in lines:
            r = reg.match(line)
            v = val.search(line)
            registers[r.group()] = int(v.group(), 16)
    return registers

def check_regs(registers, state):
    for x, y in registers.iteritems():
        try:
            r = getattr(state.regs, x)
        except Exception as e:
            # Some registers such as cs, ds, eflags etc. aren't supported in Angr
            # https://github.com/angr/simuvex/blob/master/simuvex/plugins/gdb.py#L97
            continue
        assert r.args[0] == y, "{0} doesn't match ({1}, {2})".format(x, r.args[0], y)
    print('Registers OK')


# In[ ]:

p = angr.Project('r200.bin')
# p.hook(0x400914, func=get_length, length=5)


# In[ ]:

init = p.factory.blank_state(addr=main)

regs = 'assets/regs'
stack = 'assets/stack'
heap = 'assets/heap'

init.gdb.set_stack(stack, stack_top=0x7ffffffde000)
init.gdb.set_heap(heap, heap_base=0x602000)
init.gdb.set_regs(regs)

check_regs(parse_regs(regs), init)


# In[ ]:

pgp = p.factory.path_group(init, threads=8)


# In[ ]:

ex = pgp.explore(find=win, avoid=fail)
print_paths(ex, trace=True)
print(ex)


# In[ ]:



