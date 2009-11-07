#/usr/bin/env python

import os
import sys
import Elf
import struct
import resource


from auxv             import *
from pyptrace         import *
from pyptrace.defines import *
from cStringIO        import StringIO


class landfill:
    '''
    Dump a running process to an ELF file
    '''

    ############################################################################
    def __init__(self, pid=None):
        self.pid      = pid
        self.dbg      = pyptrace()
        self.attached = False

        self.elf         = StringIO()
        self.elf_header  = None
        self.phdrs       = list()
        self.stack       = dict()
        self.stack_start = None
        self.stack_end   = None
        self.text        = None
        self.data        = None

        #self._verbose = lambda msg: sys.stdout.write(msg + "\n")
        self._verbose = lambda msg: None

    ############################################################################
    def attach(self):
        '''
        Attach to a process using ptrace.
        '''

        if (self.pid == None):
            print "%s" % "No pid specified."
            exit()
        else:
            if self.dbg.ptrace_attach(self.pid) == -1:
                print "attach failed"
                exit()
            else:
                self._verbose("Attached to pid %d" % self.pid)
                pid, exit_status = self.dbg.waitpid(self.pid, 0)
                self.attached = True

    ############################################################################
    def detach(self):
        '''
        Detach from a process using ptrace.
        '''

        if self.dbg.ptrace_detach(self.pid) == -1:
            print "detach failed"
            exit()
        else:
            self._verbose("Detached from pid %d" % self.pid)

    ############################################################################
    def doexit(self):
        '''
        A safety exit function that will detach first if needed.
        '''

        if self.attached:
            self.detach()
        self._verbose("Exiting")
        exit()

    ############################################################################
    def dynamic_array_entry_generator(self, offset):
        '''
        Iterate over the dynamic array entries.  It will automatically
        seek() via the reads.  We do an infinite loop since we don't 
        know where DT_NULL will be found.

        @type  offset: Integer
        @param offset: Offset to where the dynamic array can be found
        '''

        while 1:
            self.elf.seek(offset, 0)
            offset = offset + CPU_WORD_SIZE*2

            if CPU_WORD_SIZE == 4:
                yield Elf.Elf32Dynamic(self.elf.read(CPU_WORD_SIZE*2))
            elif CPU_WORD_SIZE == 8:
                yield Elf.Elf64Dynamic(self.elf.read(CPU_WORD_SIZE*2))

    ############################################################################
    def find_auxv_array(self):
        '''
        This function searches the stack for the auxv array.  
        Once this is found, it will attempt to find AT_PHDR and AT_PHNUM.

        @rtype  Tuple
        @return (AT_PHDR, AT_PHNUM) Number and location of program headers.
        '''

        PAGE_SIZE = resource.getpagesize()
        addr      = self.stack_start
        end       = self.stack_end - (CPU_WORD_SIZE*2) #sizeof(Elf_auxv_t)
        at_phdr   = None
        at_phnum  = None

        self._verbose("Searching the stack for program headers.")

        while (addr <= end):
            a_type = self.stack[addr]
            a_val  = self.stack[addr+CPU_WORD_SIZE]

            if a_type==AT_PAGESZ and a_val==PAGE_SIZE:
                break

            addr = addr + CPU_WORD_SIZE

        if a_type!=AT_PAGESZ or a_val!=PAGE_SIZE:
            print "Auxv table could not be found on the stack, exiting"
            self.doexit()

        while (addr <= end):
            addr = addr + (CPU_WORD_SIZE*2) #sizeof(Elf_auxv_t)
            a_type = self.stack[addr]
            a_val  = self.stack[addr+CPU_WORD_SIZE]

            if a_type==AT_PHDR:
                self._verbose("AT_PHDR  found at 0x%x, AT_PHDR  is 0x%x" % \
                    (addr,a_val))
                at_phdr = a_val
            elif a_type==AT_PHNUM:
                self._verbose("AT_PHNUM found at 0x%x, AT_PHNUM is 0x%x" % \
                    (addr,a_val))
                at_phnum = a_val
            elif a_val==AT_NULL:
                self._verbose("AT_NULL  found at 0x%x, exiting" % (addr))
                break

        return (at_phdr, at_phnum)

    ############################################################################
    def find_dynamic(self):
        '''
        Loop through the program headers and find the PT_DYNAMIC phdr.

        @rtype  Tuple
        @return (p_vaddr, p_offset) of the PT_DYNAMIC phdr
        '''

        for phdr in self.phdrs:
            if phdr.p_type == Elf.PT_DYNAMIC:
                self._verbose("found PT_DYNAMIC at 0x%x (offset 0x%x)" % \
                                (phdr.p_vaddr, phdr.p_offset))
                return (phdr.p_vaddr, phdr.p_offset)

    ############################################################################
    def find_dynamic_array_entries(self, offset):
        '''
        This will loop through every dynamic array entry and call the 
        corresponding parsing function.  Override the parsing functions
        to perform your own analysis of their contents.

        @type  offset: Integer
        @param offset: Offset to where the dynamic array can be found
        '''

        for dyn in self.dynamic_array_entry_generator(offset):
            type = \
            {
                Elf.DT_NULL            : None,
                Elf.DT_NEEDED          : None,
                Elf.DT_PLTRELSZ        : None,
                Elf.DT_PLTGOT          : self.parse_dt_pltgot,
                Elf.DT_HASH            : self.parse_dt_hash,
                Elf.DT_STRTAB          : self.parse_dt_strtab,
                Elf.DT_SYMTAB          : self.parse_dt_symtab,
                Elf.DT_RELA            : None,
                Elf.DT_RELASZ          : None,
                Elf.DT_RELAENT         : None,
                Elf.DT_STRSZ           : None,
                Elf.DT_SYMENT          : None,
                Elf.DT_INIT            : None,
                Elf.DT_FINI            : None,
                Elf.DT_SONAME          : None,
                Elf.DT_RPATH           : None,
                Elf.DT_SYMBOLIC        : None,
                Elf.DT_REL             : None,
                Elf.DT_RELSZ           : None,
                Elf.DT_RELENT          : None,
                Elf.DT_PLTREL          : None,
                Elf.DT_DEBUG           : None,
                Elf.DT_TEXTREL         : None,
                Elf.DT_JMPREL          : None,
                Elf.DT_BIND_NOW        : None,
                Elf.DT_INIT_ARRAY      : None,
                Elf.DT_FINI_ARRAY      : None,
                Elf.DT_INIT_ARRAYSZ    : None,
                Elf.DT_FINI_ARRAYSZ    : None,
                Elf.DT_RUNPATH         : None,
                Elf.DT_FLAGS           : None,
                Elf.DT_ENCODING        : None,
                Elf.DT_PREINIT_ARRAY   : None,
                Elf.DT_PREINIT_ARRAYSZ : None,
                Elf.DT_NUM             : None,
                Elf.DT_LOOS            : None,
                Elf.DT_HIOS            : None,
                Elf.DT_LOPROC          : None,
                Elf.DT_HIPROC          : None
            }.get(dyn.d_tag, None)

            if type != None:
                type(dyn)
            else:
                if dyn.d_tag == Elf.DT_NULL:
                    break
                else:
                    self._verbose("Unhandled entry: 0x%x" % dyn.d_tag)

    ############################################################################
    def find_elf_header(self):
        '''
        Find and populate an ELF header structure.
        Will also clear all section header information since it is invalid.
        '''

        self.elf.seek(0,0)
        self.elf_header             = Elf.Elf(self.elf.read(64))
        self.elf_header.myname      = "rebuilt elf header"
        self.elf_header.e_shoff     = 0
        self.elf_header.e_shentsize = 0
        self.elf_header.e_shnum     = 0
        self.elf_header.e_shstrndx  = 0

        self.elf.seek(0,0)
        self.elf.write(self.elf_header.serialize())

    ############################################################################
    def find_max_filesize(self):
        '''
        Loops through the program headers to determine the maximum filesize.

        @rtype  Integer
        @return Maximum filesize
        '''

        max_filesize = 0

        for phdr in self.phdrs:
            if phdr.p_type == Elf.PT_LOAD:
                if max_filesize < phdr.p_offset + phdr.p_filesz:
                    max_filesize = phdr.p_offset + phdr.p_filesz

        self._verbose("Max filesize is 0x%x (%d bytes)" % \
                        (max_filesize,max_filesize))
        return max_filesize

    ############################################################################
    def find_sections(self):
        '''
        Find .text/.data sections

        @rtype  Tuple
        @return (.text section location, .data section location)
        '''

        text = 0
        data = 0

        for phdr in self.phdrs:
            if phdr.p_type == Elf.PT_LOAD:
                if phdr.p_vaddr <= self.elf_header.e_entry:
                    self.text = phdr.p_vaddr
                    self._verbose("found .text section at 0x%x" % text)
                else:
                    self.data = phdr.p_vaddr - phdr.p_offset
                    self._verbose("found .data section at 0x%x" % data)

        return (self.text, self.data)
            
    ############################################################################
    def read_memory_libc(self, address, length):
        '''
        Uses libc's read() instead of ptrace's 4 byte restricted read.
        Depends on /proc/pid/mem so will not work on hardened machines (grsec).

        @type  address: Integer
        @param address: Address to read from.
        @type  length:  Integer
        @param length:  Length, in bytes, of data to read. 

        @rtype  String
        @return Buffer requested to be read.
        '''

        filename = '/proc/%d/mem' % self.pid

        try:
            fd = os.open(filename,os.O_RDONLY)
        except IOError:
            print "Unable to open %s" % filename
            self.doexit()

        if os.lseek(fd, address, os.SEEK_SET) != address:
            print "os.lseek failed"
            os.close(fd)
            self.doexit()

        buffer = os.read(fd, length)
        os.close(fd)
        return buffer

    ############################################################################
    def read_memory_ptrace(self, address, length):
        '''
        Read from the debuggee process space.
        Length must be a multiple of CPU_WORD_SIZE

        @type  address: Integer
        @param address: Address to read from.
        @type  length:  Integer
        @param length:  Length, in bytes, of data to read. 

        @return:    Read data in a list.
        '''

        if length%CPU_WORD_SIZE != 0:
            print "Invalid read_memory_ptrace() length specified: %d" % length
            print "Must be aligned to a multiple of %d" % CPU_WORD_SIZE
            self.doexit()

        data = ""

        while length > 0:
            buf     = self.dbg.ptrace_peektext(self.pid, address)
            if CPU_WORD_SIZE == 4:
                data += struct.pack("<I",buf & 0xFFFFFFFF)
            elif CPU_WORD_SIZE == 8:
                data += struct.pack("<Q",buf & 0xFFFFFFFFFFFFFFFF)
    
            length -= CPU_WORD_SIZE

        return data

    ############################################################################
    def read_proc_maps(self):
        '''
        Locate the stack of a process using /proc/pid/maps.
        Will not work on hardened machines (grsec).
        '''

        filename = '/proc/%d/maps' % self.pid

        try:
            fd = open(filename)
        except IOError:
            print "Unable to open %s" % filename
            self.doexit()

        for line in fd:
            if line.find("stack") != -1:
                fields = line.split()

                self.stack_begin,self.stack_end = fields[0].split('-')
                self.stack_start = int(self.stack_begin,16)
                self.stack_end   = int(self.stack_end,16)

                break

        fd.close()

        if self.stack_start==0 or self.stack_end==0:
            print "Unable to read stack address information via /proc, exiting."
            self.doexit()

    ############################################################################
    def read_stack(self):
        '''
        Reads the entire stack of a process.  Currently uses ptrace.

        @rtype  Dictionary
        @return Returns a self.stack dictionary of {addr:value} entries
        '''

        addr  = self.stack_start

        self._verbose("Reading the stack via ptrace.")

        while addr < self.stack_end:
            self.stack[addr] = self.dbg.ptrace_peektext(self.pid, addr)
            addr = addr + CPU_WORD_SIZE

    ############################################################################
    def read_phdrs(self, at_phdr=None, at_phnum=None):
        '''
        Using the auxv array information, read and populate the phdrs list.

        @type  at_phdr: Integer 
        @param at_phdr: Location of the program headers

        @type  at_phnum: Integer
        @param at_phnum: Number of program headers
        '''

        if at_phdr == None:
            print "Location (AT_PHDR) could not be read, exiting"
            self.doexit()
        if at_phnum == None:
            print "Number (AT_PHNUM) could not be read, exiting"
            self.doexit()

        location   = at_phdr

        for count in xrange(at_phnum):
            if CPU_WORD_SIZE == 4:
                length = len(Elf.Elf32Pheader())
                self.phdrs.append(\
                    Elf.Elf32Pheader(self.read_memory_libc(location,length)))
            elif CPU_WORD_SIZE == 8:
                length = len(Elf.Elf64Pheader())
                self.phdrs.append(\
                    Elf.Elf64Pheader(self.read_memory_libc(location,length)))

            location = location + length

    ############################################################################
    def read_pt_load(self):
        '''
        Dump PT_LOAD segments from memory.  Uses /proc memory read currently.
        '''

        for phdr in self.phdrs:
            if phdr.p_type == Elf.PT_LOAD:
                self._verbose( \
                "PT_LOAD: 0x%x bytes (0x%x-0x%x) writing to 0x%x-0x%x" % \
                (phdr.p_filesz, phdr.p_vaddr, phdr.p_vaddr + phdr.p_filesz, \
                phdr.p_offset, phdr.p_offset + phdr.p_filesz))

                ptload = self.read_memory_libc(phdr.p_vaddr, phdr.p_filesz)
                self.elf.seek(phdr.p_offset, 0)
                self.elf.write(ptload)

    ############################################################################
    def rebuild_elf(self):
        '''
        Wrapper function that will rebuild a running program from memory.
        The pid of the process must already be supplied to landfill, for example
        
        l = landfill.landfill(pid)
        l.rebuild_elf()
        '''

        if (self.pid == None):
            print "%s" % "No pid specified."
            exit()
        else:
            self.attach()

        self.elf.write('\x00' * self.find_max_filesize())

        self.read_proc_maps()
        self.read_stack()
        #self.print_stack()
        (at_phdr, at_phnum) = self.find_auxv_array()
        self.read_phdrs(at_phdr, at_phnum)
        #self.print_phdrs()
        self.read_pt_load()
        self.find_elf_header()
        self.find_sections()
        self.find_dynamic_array_entries(self.find_dynamic()[1])

        file = open("landfill_dumped.elf","wb")
        file.write(self.elf.getvalue())
        file.close()
        self.elf.close()

        self.detach()

    ############################################################################
    def parse_dt_pltgot(self, dyn):
        '''
        Callback responsible for parsing the DT_PLTGOT dynamic array entry.
        Currently this searches through the GOT for entries that have already
        been resolved in memory and unresolves them so that they point back to
        the relocation table.

        Override this function to perform your own analysis on DT_PLTGOT.

        @type  dyn: ElfXXDynamic
        @param dyn: Dynamic array entry
        '''

        dynamicv_addr  = self.find_dynamic()[0]
        filesize       = self.find_max_filesize()
        got_plt_offset = dyn.d_value - self.data
        if CPU_WORD_SIZE == 4:
            fmt = '<I'
        elif CPU_WORD_SIZE == 8:
            fmt = '<Q'

        self._verbose(".got.plt Section found at: 0x%x, file offset: 0x%x" % \
                        (dyn.d_value,dyn.d_value - self.data))

        # zero GOT[1] and GOT[2]
        # GOT[0]: .dynamic
        # GOT[1]: link_map
        # GOT[2]: _resolve (_dl_runtime_resolve)
        self.elf.seek(got_plt_offset + CPU_WORD_SIZE, 0)
        self.elf.write('\x00' * CPU_WORD_SIZE*2)

        tmp = struct.unpack(fmt, self.elf.read(CPU_WORD_SIZE))[0]

        # len(Elf32Reloc())  =  8 (0x8)
        # len(Elf32Reloca()) = 12 (0xC)
        # len(Elf64Reloc())  = 16 (0x10)
        # len(Elf64Reloca()) = 24 (0x18)
        while tmp != 0:
            if tmp < (dynamicv_addr + filesize):
                # tmp is the first unbinded entry in the GOT
                # sizeof(reloc entry) = 0x10, subtract to get start of array
                tmp = tmp - 0x10 * (((self.elf.tell() - \
                    (got_plt_offset + CPU_WORD_SIZE)) / CPU_WORD_SIZE) - 3)
                self._verbose(".rel.plt resolved to 0x%x, now fixing" % tmp)
                self.unbind_got(got_plt_offset, tmp) 
                break

            tmp = struct.unpack(fmt, self.elf.read(CPU_WORD_SIZE))[0]

            # extra +CPU_WORD_SIZE for the original tmp read() after seek
            count = ((self.elf.tell() - \
                    (got_plt_offset + CPU_WORD_SIZE))/CPU_WORD_SIZE)
            if count > 1200:
                print ".rel.plt was not found, plt unresolved"
                break

    ############################################################################
    def parse_dt_hash(self, dyn):
        '''
        Callback responsible for parsing the DT_HASH dynamic array entry.
        Currently this just locates where the .hash section is.

        Override this function to perform your own analysis on DT_HASH.

        @type  dyn: ElfXXDynamic
        @param dyn: Dynamic array entry
        '''

        if CPU_WORD_SIZE == 4:
            self.elf_header.sections.append(Elf.Elf32Section())
        elif CPU_WORD_SIZE == 8:
            self.elf_header.sections.append(Elf.Elf64Section())

        hash = self.elf_header.sections[-1]
        hash.setName(".hash")

        if self.elf_header.e_type == Elf.ET_EXEC:
            hash.sh_offset = dyn.d_value
            #XXX: hash.sh_offset = dyn.d_value - BASEADDR
        elif self.elf_header.e_type == Elf.ET_DYN: 
            hash.sh_offset = dyn.d_value
            
        #print "Symbol hash table section found at 0x%x" % hash.sh_offset

    ############################################################################
    def parse_dt_strtab(self, dyn):
        '''
        Callback responsible for parsing the DT_STRTAB dynamic array entry.
        Currently this just locates where the .strtab section is.

        Override this function to perform your own analysis on DT_STRTAB.

        @type  dyn: ElfXXDynamic
        @param dyn: Dynamic array entry
        '''

        if CPU_WORD_SIZE == 4:
            self.elf_header.sections.append(Elf.Elf32Section())
        elif CPU_WORD_SIZE == 8:
            self.elf_header.sections.append(Elf.Elf64Section())

        strtab = self.elf_header.sections[-1]
        strtab.setName(".strtab")

        if self.elf_header.e_type == Elf.ET_EXEC:
            strtab.sh_offset = dyn.d_value
            #XXX: strtab.sh_offset = dyn.d_value - BASEADDR
        elif self.elf_header.e_type == Elf.ET_DYN: 
            strtab.sh_offset = dyn.d_value
            
        #print "String table section found at 0x%x" % strtab.sh_offset

    ############################################################################
    def parse_dt_symtab(self, dyn):
        '''
        Callback responsible for parsing the DT_SYMTAB dynamic array entry.
        Currently this just locates where the .symtab section is.

        Override this function to perform your own analysis on DT_SYMTAB.

        @type  dyn: ElfXXDynamic
        @param dyn: Dynamic array entry
        '''

        if CPU_WORD_SIZE == 4:
            self.elf_header.sections.append(Elf.Elf32Section())
        elif CPU_WORD_SIZE == 8:
            self.elf_header.sections.append(Elf.Elf64Section())

        symtab = self.elf_header.sections[-1]
        symtab.setName(".symtab")

        if self.elf_header.e_type == Elf.ET_EXEC:
            symtab.sh_offset = dyn.d_value
            #XXX: symtab.sh_offset = dyn.d_value - BASEADDR
        elif self.elf_header.e_type == Elf.ET_DYN: 
            symtab.sh_offset = dyn.d_value
            
        #print "Symbol table section found at 0x%x" % symtab.sh_offset

    ############################################################################
    def print_stack(self):
        '''
        This will print out the entire sorted process stack.
        '''

        keys = self.stack.keys()
        keys.sort()

        for k in keys:
            print hex(k),self.stack[k]

    ############################################################################
    def print_phdrs(self):
        '''
        Pretty print the process's program headers.
        '''

        print "\nProgram Headers:"
        for phdr in self.phdrs:
            print phdr

    ############################################################################
    def unbind_got(self, got_plt_offset, rel_plt):
        '''
        Loop through the GOT and unbind any entries that have already been
        resolved in memory so that the dumped binary will not point to
        invalid memory addresses.

        @type  got_plt_offset: Integer
        @param got_plt_offset: Offset of the .got.plt section in the binary

        @type  rel_plt: Integer
        @param rel_plt: Location of the relocation table
        '''

        if CPU_WORD_SIZE == 4:
            fmt = '<I'
        elif CPU_WORD_SIZE == 8:
            fmt = '<Q'

        # skip GOT[0], GOT[1], and GOT[2]
        self.elf.seek(got_plt_offset + CPU_WORD_SIZE*3, 0)
        tmp = struct.unpack(fmt, self.elf.read(CPU_WORD_SIZE))[0]

        # XXX: add range checking to while loop
        while tmp != 0:
            if tmp != rel_plt + \
                    0x10*(((self.elf.tell() - got_plt_offset)/CPU_WORD_SIZE)-4):
                # this GOT entry is already resolved, undo
                #self._verbose("0x%x is resolved to 0x%x, undoing" % (rel_plt +\
                #0x10*(((self.elf.tell()-got_plt_offset)/CPU_WORD_SIZE)-4),tmp))
                tmp = rel_plt + \
                    0x10*(((self.elf.tell() - got_plt_offset)/CPU_WORD_SIZE)-4)
                self.elf.seek(self.elf.tell()-CPU_WORD_SIZE, 0)
                self.elf.write(struct.pack(fmt, tmp))

            tmp = struct.unpack(fmt, self.elf.read(CPU_WORD_SIZE))[0]
