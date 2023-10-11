---
title: "[ESAIP CTF] - Find the Matrix (500)"
date: 2022-01-02
categories: ['crypto']
draft: false
---

---
### Author : `voiv0de` 
---

The ESAIP CTF was overall a pretty cool event. Usually I take care of the Reverse Engineering challenges but on this one I returned to my first love : Cryptanalysis.

During the CTF, I managed to obtain two first bloods in this category 🩸. 

Today, I present to you : **Find the Matrix.**

```
The flag was encrypted by this algorithm, find a way to reverse it to get the flag!
```

Attached to it were two files : 

```python
# chall.py
import numpy as np
from math import sqrt
from sympy import Matrix
from random import choice

BLOCK_SIZE = 4

I = [
    [1, 2],
    [3, 4]
]

def to_hex(x):
    res = ""
    for i in [hex(k)[2:] for k in sum(x, [])]:
        if len(i) == 1:
            res += f"0{i}"
        else:
            res += i
    return res

def to_plain(x):
    res = ""
    for i in [chr(k) for k in sum(x, [])]:
        res += i
    return res

def pad(b:bytes, size:int):
    while len(b)%size != 0:
        b += b"\x03"
    return b

def to_m(b:bytes):
    return [[j for j in b[i:i+int(sqrt(BLOCK_SIZE))]] for i in range(0,len(b), int(sqrt(BLOCK_SIZE)))]

def block(a:bytes):
    return [a[i:i+BLOCK_SIZE] for i in range(0,len(a), BLOCK_SIZE)]

def xor(a, b):
    return [[int(i)^int(j) for i,j in zip(a[t], b[t])] for t in range(len(a))]

def encrypt_block(block:bytes, key:list):
    m_key = np.array(key)
    m_block = np.array(to_m(block))
    m_cipher = np.matmul(m_block, m_key)%255
    return m_cipher.tolist()[0]

def decrypt_block(block:bytes, key:list):
    """ Nothing here """
    
def gen_keys(b_keys:list, length:int, d=False):
    k = []
    for b_k in b_keys:
        m_b_k = Matrix(to_m(b_k))
        while 1:
            try:
                m_b_k_inv = m_b_k.inv_mod(255)
                if d:
                    k_to_add = m_b_k_inv
                else:
                    k_to_add = m_b_k
                k.append(k_to_add.tolist())
                break
            except ValueError:
                m_b_k = m_b_k.add(Matrix(I))
                continue
    
    for i in range(length-len(k)):
        k.append(k[i])
    return k
        

flag = pad(open("flag.txt", "rb").read(), 16)
k = pad(choice(open("/usr/share/wordlist/rockyou.txt", "r", errors='ignore', encoding='utf-8').readlines()).strip("\n").encode(), 16)

print(k)
b_flag = block(flag)
b_keys = block(k)

iv = "_IV_"
m_iv = to_m(iv.encode())

cipher = ""

for b, k in zip(b_flag, gen_keys(b_keys, len(b_flag))):
    m_b = to_m(b)
    b_xored = xor(m_iv, m_b)
    c = encrypt_block(b_xored, k)
    cipher += to_hex(c)
    m_iv = c

print(dict(cipher=cipher, iv=iv, key=""))
```

```
output.txt
{'cipher': '470002d269574fc2705cfd6f5f05b4b2b53c6f9d1432d78d5277b7d83dea85f56f92c506c136ea71b844f8baf09c50a20ba62a06b47e7e119a4876aa6784f711d8bb33a2be36848808b3faf8bc003079', 'iv': '_IV_', 'key': ''}
```

---

## Analyzing the code 

So what do we have ? The algorithm is dividing the flag into blocks of for bytes, which are then transformed into 2x2 matrixes and xored with the previous block (the first block will be xored with the IV "`_IV_`").

Moreover, we see a function named `encrypt_block()` which takes a key as an argument. This key is a random line from `rockyou.txt` (which is 14344391 lines long so bruteforcing could take some time). The chosen key is padded with "\x03̀" bytes until it is 16 bytes long before being divided into blocks of 4 bytes each. The `encrypt_block()` function then turn those bytes into another 2x2 matrix. The ciphertext will be the product of the cleartext matrix and the key matrix (modulo 255).

---

## Reversing the algorithm

The first thing I like to do on those kind of challenges is encrypting a known string with the algorithm. Personnally, since the key is 16 bytes long I chose the string "`0123456789abcdef`". We will also choose a random line of the `rockyou.txt` as the key to use for our tests.

It gives us the following parameters : 
```python
flag = b"0123456789abcdef"
key = b'REFUGIO\x03\x03\x03\x03\x03\x03\x03\x03\x03'
```
By running the algorithm we obtain the following : 
 
<img src="https://i.imgur.com/veQMdjy.png" class="wuimages">
 
Now we can work ! 
 
The reversing of the algorithm is actually pretty straightforward. The conversion between blocks and matrixes can easily reverted. The xor with the previous block is also trivial to invert thanks to the properties of `xor`. However, the encrypt_block function is a little trickier. 
 
```python
def encrypt_block(block:bytes, key:list):
    m_key = np.array(key)
    m_block = np.array(to_m(block))
    m_cipher = np.matmul(m_block, m_key)%255
    return m_cipher.tolist()[0]
```

The function takes the current block (xored with the previous one) and the current key block. Those are turned to matrixes and the output is the product of those two matrixes.

Is it possible to revert it ? Yeah, but not with a simple division because those are not possible with matrixes. But what is a division anyway ?

Let's say `x`, `y` and `z` are reals and `x * y = z`.
Then `z / y = x` or put differently `z * y^-1 = x`.

For matrixes, division does not exist but you can invert matrixes. So, based on the output matrix and the key, `output * key^-1 = input`.

And, luckily for us, the creator of the programm already gave us the means to invert matrixes in the `gen_keys()` function by just setting the parameter `d` to `True`.

```python
def gen_keys(b_keys:list, length:int, d=False):
    k = []
    for b_k in b_keys:
        m_b_k = Matrix(to_m(b_k))
        while 1:
            try:
                m_b_k_inv = m_b_k.inv_mod(255)
                if d:
                    k_to_add = m_b_k_inv
                else:
                    k_to_add = m_b_k
                k.append(k_to_add.tolist())
                break
            except ValueError:
                m_b_k = m_b_k.add(Matrix(I))
                continue

    for i in range(length-len(k)):
        k.append(k[i])
    return k
```
 
We now have the means to decrypt our homemade ciphertext !
 
```python
# Yeah, this function is basically the same of the encrypt_block function 
# It could be cleaner but CTF are what they are ;)
def decrypt_block(block:bytes, key:list):
    m_key = np.array(key)
    m_block = np.array(to_m(block))
    m_decrypt = np.matmul(m_block, m_key) % 255
    return m_decrypt.tolist()

cipher = "7b c9 77 89 11 94 f5 d7 b6 8d 94 de d2 92 1c c6".split(" ")
K = b'REFUGIO\x03\x03\x03\x03\x03\x03\x03\x03\x03'
b_keys = block(K)

iv = "_IV_"
m_iv = to_m(iv.encode())

flag = ""

for i in range(0, len(cipher), 4):
    k = gen_keys(b_keys, len(flag) // BLOCK_SIZE, d=True)
    c = [[0, 0], [0, 0]]
    c[0][0] = int(cipher[i], 16)
    c[0][1] = int(cipher[i+1], 16)
    c[1][0] = int(cipher[i+2], 16)
    c[1][1] = int(cipher[i+3], 16)
    b_xored = decrypt_block(c, k)
    b_xored = b_xored[(i//4) % 4]
    m_b = xor(m_iv, b_xored)
    m_iv = c
    for i in m_b:
        for j in i:
            flag += chr(j)

print(flag)
```
<img src="https://i.imgur.com/bhNaP8Z.png" class="wuimages">

---

## Finding the right password
Our algorithm is working, put we still have one tiny problem before we can flag. If you remember the code from the challenge, the password is selected this way : 

```python
k = pad(choice(open("./rockyou.txt", "r", errors='ignore', encoding='utf-8').readlines()).strip("\n").encode(), 16)
```

The password is selected from `rockyou.txt` using the function `choice()` from the `random` library. And the seed is unknown to us. And bruteforcing the 14344391 passwords would take too long. However, we know the first later of the flag (in our case `ECTF\{`) so we can reduce the number of passwords to try out by finding the 4 first bytes of the key with a known plaintext attack.

We know the IV is `_IV_` and won't move so it will not be of any problem to us. Now we could solve an equation to find the 4 bytes we are searching for. Or we could be lazy and just bruteforce with all the password and print the ones that give us a plaintext starting with ECTF ;).

```python
cipher = "47 00 02 d2 69 57 4f c2 70 5c fd 6f 5f 05 b4 b2 b5 3c 6f 9d 14 32 d7 8d 52 77 b7 d8 3d ea 85 f5 6f 92 c5 06 c1 36 ea 71 b8 44 f8 ba f0 9c 50 a2 0b a6 2a 06 b4 7e 7e 11 9a 48 76 aa 67 84 f7 11 d8 bb 33 a2 be 36 84 88 08 b3 fa f8 bc 00 30 79".split(" ")

f = open("dump", "w") # Logging the results in case we miss something

iv = "_IV_"
m_iv = to_m(iv.encode())

flag = ""
passwd = open("./rockyou.txt", "r", errors='ignore', encoding='utf-8').readlines()

print("Finished reading rockyou.txt")

for line in passwd:
    iv = "_IV_"
    m_iv = to_m(iv.encode())
    flag = ""
    if line.strip("\n").encode() == b"":
        continue
    K = pad(line.strip("\n").encode(), 16)
    b_keys = block(K)
    for i in range(0, len(cipher), 4):
        k = gen_keys(b_keys, len(flag) // BLOCK_SIZE, d=True)
        c = [[0, 0], [0, 0]]
        c[0][0] = int(cipher[i], 16)
        c[0][1] = int(cipher[i+1], 16)
        c[1][0] = int(cipher[i+2], 16)
        c[1][1] = int(cipher[i+3], 16)
        b_xored = decrypt_block(c, k)
        b_xored = b_xored[(i//4) % 4]
        m_b = xor(m_iv, b_xored)
        m_iv = c
        for i in m_b:
            for j in i:
                flag += chr(j)
    if "ECTF" in flag:
        print(flag, line)
        f.write(flag)
        f.write(line)

f.close()
```

<img src="https://i.imgur.com/5Z4Psiv.png" class="wuimages">


I'm starting to see a pattern don't you ?
Let's create a file which will be a little less hefty.

<img src="https://i.imgur.com/cntR5G0.png" class="wuimages">

Okay, now what can we do ? We know the next char of the flag (`{`) but we have no clue about what the 3 following bytes will look like. So we bruteforce again but this time with our newly created file.

```python
cipher = "47 00 02 d2 69 57 4f c2 70 5c fd 6f 5f 05 b4 b2 b5 3c 6f 9d 14 32 d7 8d 52 77 b7 d8 3d ea 85 f5 6f 92 c5 06 c1 36 ea 71 b8 44 f8 ba f0 9c 50 a2 0b a6 2a 06 b4 7e 7e 11 9a 48 76 aa 67 84 f7 11 d8 bb 33 a2 be 36 84 88 08 b3 fa f8 bc 00 30 79".split(" ")

f = open("dump", "w") # Logging the results in case we miss something

iv = "_IV_"
m_iv = to_m(iv.encode())

flag = ""
passwd = open("./list.txt", "r", errors='ignore', encoding='utf-8').readlines()

print("Finished reading list.txt")

for line in passwd:
    iv = "_IV_"
    m_iv = to_m(iv.encode())
    flag = ""
    if line.strip("\n").encode() == b"":
        continue
    K = pad(line.strip("\n").encode(), 16)
    b_keys = block(K)
    for i in range(0, len(cipher), 4):
        k = gen_keys(b_keys, len(flag) // BLOCK_SIZE, d=True)
        c = [[0, 0], [0, 0]]
        c[0][0] = int(cipher[i], 16)
        c[0][1] = int(cipher[i+1], 16)
        c[1][0] = int(cipher[i+2], 16)
        c[1][1] = int(cipher[i+3], 16)
        b_xored = decrypt_block(c, k)
        b_xored = b_xored[(i//4) % 4]
        m_b = xor(m_iv, b_xored)
        m_iv = c
        for i in m_b:
            for j in i:
                flag += chr(j)
    if "ECTF{" in flag:
        print(flag, line)
        f.write(flag)
        f.write(line)

f.close()
```
<img src="https://i.imgur.com/JAwrfNo.png" class="wuimages">

Looks like a flag to me ;). It means the password we were looking for is **ilove2shop**.

Thanks to all the organizers of the ESAIP CTF and to [Ruulian](https://0xhorizon.eu/) for this challenge which was a lot of fun to solve 🥳. See you next year !