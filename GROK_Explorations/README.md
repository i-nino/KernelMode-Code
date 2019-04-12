
# GROK Vault7 Kernel-Mode Rootkit

Demonstrates GROK's use of manipulating the stack in order to make "hidden" function calls.  It does it only in the kernel, but the concept can be applied to user-mode code just the same, as demonstrated above, where the native NtQuerySystemInformation is demoed to just print the imagebase and drivername of each driver on the system, in similar fashion as GROK does (outside of the useless printing of course).  The implementation is in "hiddenCall.asm".
