ROP detector
============

Description
-------------

ROP detector is a small experimental tool for ROP-shellcode detection.
ROP detector injects a small library in address space of analyzed process.
This library provides the ROP detector with information about address space
and current state of analyzed process. It also creates an emulator that
has all address space of this process (the emulator copy address space
with copy_on_write technique, so in does not take a lot of physical memory).
Kernel module provides ROP detector with important information about current 
processes address spaces.
ROP detector reads network traffic and uses different techniques 
(static and dynamic analysis) in order to detect ROP-shellcodes.

Main components:
* Kernel module
* ROP detector
* Libinject

Compilation
-------------
make

Usage
-------------
* sudo insmod ./bin/rop.ko # kernel module installation
* sudo ./bin/rop_detector -p process_pid -i eth0 # detect ROP-shellcodes for the analyzed process from eth0 interface

Third party libraries used
-------------

* libudis86 [http://udis86.sourceforge.net/]
* libdisasm [https://sourceforge.net/projects/bastard/files/libdisasm/]
* hotpatch [https://github.com/vikasnkumar/hotpatch]
* libemu [https://github.com/buffer/libemu]
* Red-Black Tree C Code [http://web.mit.edu/~emin/Desktop/ref_to_emin/www.old/source_code/red_black_tree/index.html]