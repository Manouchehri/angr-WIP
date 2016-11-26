#!/usr/bin/env python2

# Author: David Manouchehri <manouchehri@protonmail.com>

import angr

def main():
    proj = angr.Project('./rev1', load_options={"auto_load_libs": False}) # Disabling the automatic library loading saves a few milliseconds.

    initial_state = proj.factory.entry_state(args=["./rev1"]) 

    # Force all the chars to be within the expected ASCII values
    for _ in xrange(31):
        k = initial_state.posix.files[0].read_from(1)
        initial_state.se.add(k >= ord(' '))
        initial_state.se.add(k <= ord('~'))

    k = initial_state.posix.files[0].read_from(1) # Reset
    initial_state.se.add(k == 10) # Force a newline.

    initial_state.posix.files[0].seek(0) # Reset back to the first char

    # Make the first few chars printable
    #for _ in xrange(10):
#   k = initial_state.posix.files[0].read_from(1)
#        initial_state.se.add(k >= ord('A'))
#        initial_state.se.add(k <= ord('z'))    


    # k = initial_state.posix.files[0].read_from(1) # Reset
    # initial_state.se.add(k == 10) # Force a newline.

    initial_state.posix.files[0].seek(0)
    initial_state.posix.files[0].length = 32

    initial_path = proj.factory.path(initial_state)
    path_group = proj.factory.path_group(initial_state)
    
    path_group.explore(find=0x8048568, avoid={0x0804846E, 0x80486ca})

    found = path_group.found[0] # In our case, there's only one printable solution.
    solution = found.state.posix.dumps(0)
    # solution = fetch[:fetch.find("}")+1] # Trim off the null bytes at the end of the flag (if any).
    return solution

def test():
    assert main() == ''

if __name__ == '__main__':
    print(repr(main()))
