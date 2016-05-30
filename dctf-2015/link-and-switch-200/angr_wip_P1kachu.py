
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

def patch_fgets(state):
    addr = state.regs.rsi.args[0]
    length = state.regs.rdi.args[0]
    print("{0} bytes read at {1}".format(addr, hex(length)))
    for x in xrange(length):
        state.mem[addr + x:] = state.se.BVS('c', 8)


# In[ ]:

p = angr.Project('r200.bin')
p.hook(0x40091c, func=patch_fgets, length=5)


# In[ ]:

init = p.factory.blank_state()

init.gdb.set_stack('binaries/r200/stack', stack_top=0x7ffffffde000)
print("Stack set")

init.gdb.set_heap('binaries/r200/heap', heap_base=0x602000)
print("Heap set") 

# https://github.com/angr/simuvex/blob/efa097d4076401cbd48277223e1340d7c6dffbc1/simuvex/plugins/gdb.py#L97
# Some registers such as cs, ds, eflags etc. aren't supported in Angr
init.gdb.set_regs('binaries/r200/regs')
print("Registers set")


# In[ ]:

pgp = p.factory.path_group(init, threads=8)


# In[ ]:

ex = pgp.explore(find=win, avoid=fail)

print(ex)

