![landfill](http://github.com/cloudburst/landfill/tree/master/landfill.png?raw=true)

## Landfill

[`landfill`] is a Python library for dumping a running Linux process from memory and rebuilding it into an ELF file that can then be run on any system.  It is heavily based on the [`process dumper`] tool by ilo.  The library works by attaching to a process using ptrace and then rebuilding the program using only the auxv vector found on the stack.  It supports both 32bit and 64bit.

## Usage

First the Python dependencies must be installed:

    git clone git://github.com/cloudburst/pyptrace.git
    git clone git://github.com/cloudburst/Elf.git
    git clone git://github.com/cloudburst/landfill.git

Then:

    >>> import landfill
    >>> l = landfill.landfill(pid)
    >>> l.rebuild_elf()

A sample utility is also included as sample/dump_process_from_memory.py that will fill in the pid at runtime.

## References

- [ilo - Advances in remote-exec AntiForensics][1]
- [grugq & scut - Armouring the ELF: Binary encryption on the UNIX platform][2]
- [Chris Rohlf - No Section Header? No Problem][3]
- [Chris Rohlf - Resolving ELF Relocation Name / Symbols][4]
- [herm1t - INT 0x80? No, thank you!][5]

[1]: http://www.phrack.org/issues.html?issue=63&id=12
[2]: http://phrack.org/issues.html?issue=58&id=5
[3]: http://em386.blogspot.com/2006/10/elf-no-section-header-no-problem.html
[4]: http://em386.blogspot.com/2006/10/resolving-elf-relocation-name-symbols.html
[5]: http://vx.netlux.org/lib/vhe05.html

## TODO

- Add file launching
- Add stricter bounds checking
- Remove ptrace dependency with kernel module
- Add section rebuilding
- Add symbol rebuilding
- Add core file rebuilding
