# Shellcode / Reverse Engineering

## General


Search man pages (for syscalls)
```bash
$ man -k write
# open man pages for syscall
$ man 2 write
```

Find CPU information
```bash
$ cat /proc/cpuinfo
$ cat /proc/cpuinfo | grep processor | wc -l
# check number of cores
$ cat /proc/cpuinfo | grep 'core id'  
$ lscpu
```

Get architecture information
```bash
$ uname -a
```

Enumerate external libraries being used
```bash
$ lddtree ./test
test => ./test (interpreter => /lib64/ld-linux-x86-64.so.2)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
        ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2
```

Quickly disassemble opcodes
```bash
$ echo -ne "\x6A\x7F\x5A\x54\x59\x31\xDB\x6A\x03\x58\xCD\x80\x51\xC3" | ndisasm -u -
```


Calculate address of function
```bash
# module's base address + offset of symbol = function address
```

## Protection

### ASLR

Identify ASLR (Windows): [Address Space Layout Randomization (ASLR)](https://docs.microsoft.com/en-us/previous-versions/bb430720(v=msdn.10)?redirectedfrom=MSDN#address-space-layout-randomization-aslr)

Enable/Disable ASLR
```bash
0 = Disabled
1 = Conservative Randomization
2 = Full Randomization

$ sysctl -a --pattern "randomize"
```

Disable ASLR temporarily:
```bash
sudo /sbin/sysctl -w kernel.randomize_va_space=0
```

Check for ASLR. Start address of libc has always different value if enabled.
```bash
$ for i in {1..3}; do ldd test | grep libc; done
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f6f07591000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2086ac7000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ff8f64f7000)
```

## Handling binary output

Convert between different bases
```bash
$ echo 'obase=16;127' | bc
# 7F
$ echo 'obase=10;ibase=16;C' | bc
# 12
```

Stdout to hex
```bash
$ echo -n "HelloWorld" | od -A n -t x1
# 48 65 6c 6c 6f 57 6f 72 6c 64
```

Write bytes to stdin
```bash
# python 2
$ python -c "import sys; sys.stdout.write('\x41' * 3)"

# python 3
$ python -c "import sys; sys.stdout.buffer.write('\x41' * 3)"
```

Number to hex codes
```python
import struct
data = struct.pack('<I', 0x61626364)
data = ''.join('\\x{:02X}'.format(a) for a in data)
print(data)
# \x64\x63\x62\x61
```

## Handling ELF

Get entry point of binary
```bash
$ readelf -h ./binary | grep Entry
  Entry point address:               0x8048370
```

Dump ELF header
```bash
$ dumpelf ./helloworld
```

## objdump

Disassemble binary file
```bash
$ objdump -d -M intel ./binary
```

Get shellcode of binary
```bash
# always compare results from different commands

$ echo "\"$(objdump -d ./binary | grep '[0-9a-f]:' | cut -d$'\t' -f2 | grep -v 'file' | tr -d " \n" | sed 's/../\\x&/g')\""

$ objdump -d ./binary |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

## nasm

Assemble and link
```bash
$ nasm -f elf32 -o helloworld.o helloworld.nasm
$ gcc -m32 -o helloworld helloworld.o

# or link with ld see below
```

Special tokens
```
$   evaluates to the current line
$$  evaluates to the beginning of current section
```

## Linker

Get linker information:
```bash
$ ld -V
GNU ld (GNU Binutils for Debian) 2.20.1-system.20100303
  Supported emulations:
   elf_i386
   i386linux
   elf_x86_64
   elf_l1om
```

Link binary
```bash
$ ld -m elf_i386 -o helloworld helloworld.o 
```

Set custom entry point
```bash
$ ld -e my_entry_point -o helloworld helloworld.o
```


## nm

```
nm -n ./file            in sorted order
nm -S ./file            display size
nm -g ./file            list external symbols
nm ./file | grep ' B '  all in bss section
nm -a ./file            display all debug symbols
```

## strace

```
strace ./file
strace -o out.log ./file    write output to file
strace -t                   use timestamp
strace -r                   use relative timestamp
strace -e read,write        trace only specific syscalls
strace -p <pid>             attach to running proc
strace -c                   show statistics on syscalls

strace -e socket,connect,sendmmsg nc google.com 80
strace -e connect nc google.com 80 | grep 53
```

## gcc

Disable stack protection and make stack executable:
```bash
gcc -fno-stack-protection -z execstack helloworld.c
```

```
-g                      compile with debugging symbols
-ggdb                   compile with GDB specific symbols
-O0                     no optimization
-fno-builtin            dont replacement of functions with builtin ones
-Wall                   enable warnings on questionable constructions
-pedantic               issue all the warnings demanded by strict ISO
-pedantic-errors        treat warnings as errors
-std=c11                use C11 C standard 
```

## Shellcode Techniques

### Jump-Call-Pop

Generate position independant shellcode (PID)

```asm
jmp short call_shellcode

shellcode:
    ; shellcode goes here

call_shellcode:
call shellcode
    ; this will push the string's address
    ; onto the stack and ensures access at runtime!
HelloWorld db "Hello World!", 0xa
```

### Stack Technique

Push string in reverse order onto stack.

```python
code = 'Hello World\n'
encoded = code[::-1].encode('utf-8').hex()

# '0a646c726f57206f6c6c6548'
```

## gdb

Permanently set `disassembly-flavor`
```bash
$ echo 'set disassembly-flavor intel' > ~/.gdbinit
```

Feed inline python to stdin
```
(gdb) r < <(python -c "print '\x41' *36" | binary)
(gdb) r <<< $(python -c "print '\x41' *36")
```

View source code
```
list <line number>          
```

### info
```
info registers              list all registers
info functions              all function names
info functions strcpy       all functions matching "strcpy"
info sources                source files in the program
info files                  shows all files in use
info variables              list global/static variables
info scope <function>       list variables local to <function>
```

### Breakpoints
```
info breakpoints        list all breakpoints
enable <number>		      enable breakpoint <number>
disable <number>		    disable breakpoint <number>
delete <number>					remove breakpoint <number>
break <funcname>        break @ function
break *<address>        break @ address

condition 1 i == 5      only break on bp 1 i == 5
condition 1 $eax = 0 
```

### Print
```
print variable1         print value of variable1
print/x &variable1      print address of variable1
print(/fmt) $<register> print value of register (in format)
```

### Navigation
```
run "arg1 arg2 arg3"    starts program with args
continue                continue program execution
stepi [N]               step one instruction
step [N]                step one line in code
next [N]                steps over a subroutine
nexti [N]               steps one instruction
```

### set

Set or create variables
```
set {char [4]} 0x08040000 = "Ace"
set {char} 0x.. = 'A'         interpret 'A' as {char} and set 0x..
set {..} &var = ..
set $eip = <address>          set EIP to new address
set $eax = 10                 set EAX to value 0xa

# set convenience variables
set $i = 10                   create convenient variable
set $dyn = (char *)malloc(10)
$demo = "Michael"             assign new value
set argv[1] = $demo           assign value of conv. var to existing one
```

### Logging
```
set logging file output.log     log to file
set logging on/off
show logging                    show status
set logging redirect on         output only to log
```

### Dashboard
```
help dashboard
help dashboard assembly 
help dashboard assembly -style 
dashboard assembly -style context 20
dashboard stack
dashboard stack
dashboard source
dashboard threads 
```

Load symbol file separately
```
symbol-file <file>
```
