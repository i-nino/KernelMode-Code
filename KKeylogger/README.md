Windows KernelMode keylogger, based off of original Klog1 from rootkit.com 
but modified for efficient memory usage and x64 support.  Tested on latest
Win10x64 2018 Spring Release.   Comically, undetectable (outside of the fact
you can't really load it w/o disabling the driver signing policy lol )

Disable driver signing policy:  cmd> bcdedit /set testsigning on 



!()(KernelMode-Code/KKeylogger/Demo.PNG)
