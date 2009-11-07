#/usr/bin/env python

from ctypes import *

###############################################################################
AT_NULL     = 0        # End of vector 
AT_IGNORE   = 1        # Entry should be ignored 
AT_EXECFD   = 2        # File descriptor of program 
AT_PHDR     = 3        # Program headers for program 
AT_PHENT    = 4        # Size of program header entry 
AT_PHNUM    = 5        # Number of program headers 
AT_PAGESZ   = 6        # System page size 
AT_BASE     = 7        # Base address of interpreter 
AT_FLAGS    = 8        # Flags 
AT_ENTRY    = 9        # Entry point of program 
AT_NOTELF   = 10       # Program is not ELF 
AT_UID      = 11       # Real uid 
AT_EUID     = 12       # Effective uid 
AT_GID      = 13       # Real gid 
AT_EGID     = 14       # Effective gid 
AT_CLKTCK   = 17       # Frequency of times() 

# Some more special a_type values describing the hardware.  
AT_PLATFORM = 15       # String identifying platform.  
AT_HWCAP    = 16       # Machine dependent hints about
                       # processor capabilities.  

# This entry gives some information about the FPU initialization
#  performed by the kernel.  
AT_FPUCW    = 18       # Used FPU control word.  

# Cache block sizes.  
AT_DCACHEBSIZE  = 19   # Data cache block size.  
AT_ICACHEBSIZE  = 20   # Instruction cache block size.  
AT_UCACHEBSIZE  = 21   # Unified cache block size.  

# A special ignored value for PPC, used by the kernel to control the
#  interpretation of the AUXV. Must be > 16.  
AT_IGNOREPPC    = 22   #Entry should be ignored.  

AT_SECURE   = 23       #Boolean, was exec setuid-like?  

# Pointer to the global system page used for system calls and other
#   nice things.  
AT_SYSINFO  = 32
AT_SYSINFO_EHDR = 33

###############################################################################
class Elf32_auxv(Structure):
    class a_union(Union):
        _fields_ = [("a_val",c_long),
                    ("a_ptr",c_void_p),
                    ("a_fcn",c_void_p)] #XXX: CFUNCTYPE(None,None)?

    _fields_ = [("a_type", c_int),
                ("a_un",a_union)]

###############################################################################
class Elf64_auxv(Elf32_auxv):
    _fields_ = [("a_type", c_long),
                ("a_un",Elf32_auxv.a_union)]
