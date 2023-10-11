---
title: "[HeroCTF v4] - My Passwords (492)"
date: 2023-05-12
categories: ['forensics']
draft: false
---
---
### Author : `baddhack` 
---
## Challenge Informations

### Description
```
We have exfiltrated data from a malicious person's computer and we need his pastebin password.

Unfortunately, the file system dump was damaged, so the only thing we were able to recover is provided to you.

Can you recover his password ?
```

### Flag format :

`Hero{pastebin_mdp}`

### Challmaker

`Worty`

---

## **WriteUp**

In this challenge we are provided with a *.zip* file which contains a **Firefox** directory. When you unzip the file and look into this directory here is what you see :

```bash
┌──(baddhack㉿kali)-[~/Documents/HeroCTF/forensics/dump]
└─$ ls Firefox
'Crash Reports'   installs.ini  'Pending Pings'   Profiles   profiles.ini
```

By looking briefly at every files / folders, we can easily deduct that the interesting folder is **Profiles.**

Let’s see what it contains :

```bash
┌──(baddhack㉿kali)-[~/…/HeroCTF/forensics/dump/Firefox]
└─$ ls Profiles 
nh7x18gj.default-release  tw9muaaw.default
```

Here we can see 2 profiles and only *nh7x18gj* is containing all the files that we can find in a **Firefox Profile**. When you are using Firefox, you have a dedicated folder which stores all changes you make in Firefox (home page, bookmarks, extensions and **passwords**)

<center>
  <img src="https://c.tenor.com/gVHHuzDLos8AAAAC/tiens-tiens-tiens-booba.gif"/>
</center>

As we are looking for a pastebin password, it is most likely stored in the Firefox password manager.

In Firefox documentation we can find these informations :

> **Passwords :**

- key4.db
- logins.json

Your passwords are stored in these two files. For more information, see Password Manager - Remember, delete and edit logins and passwords in Firefox.
> 

Let’s take a look at these files :

***key4.db :***

It is not very explicit and nobody wants to understand all the lines in this file. The important thing to remember is that it contains the master key of the Firefox password manager.

```bash
┌──(baddhack㉿kali)-[~/…/dump/Firefox/Profiles/nh7x18gj.default-release]
└─$ strings key4.db
SQLite format 3
+tablemetaDatametaData
CREATE TABLE metaData (id PRIMARY KEY UNIQUE ON CONFLICT REPLACE, item1, item2)/
indexsqlite_autoindex_metaData_1metaData        B
[indexckaidnssPrivate
CREATE INDEX ckaid ON nssPrivate (a102)@
WindexlabelnssPrivate
CREATE INDEX label ON nssPrivate (a3)F
_indexsubjectnssPrivate
CREATE INDEX subject ON nssPrivate (a101)C
[indexissuernssPrivate
CREATE INDEX issuer ON nssPrivate (a81)
otablenssPrivatenssPrivate
CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a12, a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a8a, a8b, a90, a100, a101, a102, a103, a104, a105, a106, a107, a108, a109, a10a, a10b, a10c, a110, a111, a120, a121, a122, a123, a124, a125, a126, a127, a128, a129, a130, a131, a132, a133, a134, a160, a161, a162, a163, a164, a165, a166, a170, a180, a181, a200, a201, a202, a210, a300, a301, a302, a400, a401, a402, a403, a404, a405, a406, a480, a481, a482, a500, a501, a502, a503, a40000211, a40000212, a80000001, ace534351, ace534352, ace534353, ace534354, ace534355, ace534356, ace534357, ace534358, ace534364, ace534365, ace534366, ace534367, ace534368, ace534369, ace534373, ace534374, ace536351, ace536352, ace536353, ace536354, ace536355, ace536356, ace536357, ace536358, ace536359, ace53635a, ace53635b, ace53635c, ace53635d, ace53635e, ace53635f, ace536360, ace5363b4, ace5363b5, ad5a0db00)3
indexsqlite_autoindex_nssPrivate_1nssPrivate
0a0B
4Egs
password
+TD
0a0B
zE#l
sig_key_0f1328d9_000000110
0P0B
password
sig_key_0f1328d9_00000011
```

***logins.json :***

This file contains all the passwords registered in the password manager. Of course they are encrypted. At the end, we can see 2 occurences about **pastebin.com**

```bash
┌──(baddhack㉿kali)-[~/…/dump/Firefox/Profiles/nh7x18gj.default-release]
└─$ jq . logins.json
{
"nextId": 7,
"logins": [
{
"id": 1,
"hostname": "[https://fr-fr.facebook.com](https://fr-fr.facebook.com/)",
"httpRealm": null,
"formSubmitURL": "[https://fr-fr.facebook.com](https://fr-fr.facebook.com/)",
"usernameField": "email",
"passwordField": "pass",
"encryptedUsername": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECOpCiXQJ8GKeBBjTGAQqzrFAyJk0Gu1z2rtKkHXWHw0p5VU=",
"encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECMbQffhGoplmBBjVnnsb1AbfO3grWoI8+pJ+lHp181NQlOY=",
"guid": "{272b19a7-728e-4d49-b279-17a8c841622f}",
"encType": 1,
"timeCreated": 1653317933832,
"timeLastUsed": 1653317933832,
"timePasswordChanged": 1653317933832,
"timesUsed": 1
},
{
"id": 2,
"hostname": "[https://www.reddit.com](https://www.reddit.com/)",
"httpRealm": null,
"formSubmitURL": "[https://www.reddit.com](https://www.reddit.com/)",
"usernameField": "username",
"passwordField": "password",
"encryptedUsername": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECNzfH+tRuHwABBAmBgPX6jQKUOsrB6tCJ44w",
"encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIs7W9C1Ej/sBBhQs+caPIx44bFELCrfzeStoB2Cp20J0MY=",
"guid": "{9f3d5059-0841-4c79-a77c-162569364aaa}",
"encType": 1,
"timeCreated": 1653317961380,
"timeLastUsed": 1653317961380,
"timePasswordChanged": 1653317961380,
"timesUsed": 1
},
{
"id": 3,
"hostname": "[https://twitter.com](https://twitter.com/)",
"httpRealm": null,
"formSubmitURL": "[https://twitter.com](https://twitter.com/)",
"usernameField": "email",
"passwordField": "password",
"encryptedUsername": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECAt+5dn0mEYbBBjFbZVHtAqRvSDWLQCWW3bbVe8ZdODR3lU=",
"encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECHE0YGtCZj1oBBiY41mrHYs+Gi4Spo69t7TCpzhgaJPgW7U=",
"guid": "{c058b846-9126-417e-ad62-ef2bc642deb4}",
"encType": 1,
"timeCreated": 1653317973205,
"timeLastUsed": 1653317973205,
"timePasswordChanged": 1653317973205,
"timesUsed": 1
},
{
"id": 4,
"hostname": "[https://accounts.google.com](https://accounts.google.com/)",
"httpRealm": null,
"formSubmitURL": "[https://accounts.google.com](https://accounts.google.com/)",
"usernameField": "identifier",
"passwordField": "password",
"encryptedUsername": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECMlnprPnwN40BBjKT869xUO4Jp/lQVPk14UQLbqqTh6IYKY=",
"encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECMg+RhMhdROMBBj3S39RQsAMbxQX5knpK17MaxzM42jiSj4=",
"guid": "{1bc4d97f-7248-4991-ac3d-8f00f7df37b3}",
"encType": 1,
"timeCreated": 1653317986174,
"timeLastUsed": 1653317986174,
"timePasswordChanged": 1653317986174,
"timesUsed": 1
},
{
"id": 5,
"hostname": "[https://pastebin.com](https://pastebin.com/)",
"httpRealm": null,
"formSubmitURL": "[https://pastebin.com](https://pastebin.com/)",
"usernameField": "LoginForm[username]",
"passwordField": "LoginForm[password]",
"encryptedUsername": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECA1XFI5iCJMzBBAWSQBwp7VKo2cYSW+cW8RD",
"encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECOThP7XPXvkcBBhQMfiZl4Yd5Yv71osCsB//O4sEWgD4qX4=",
"guid": "{851558dc-4eac-4c4a-874a-92f81bfdd623}",
"encType": 1,
"timeCreated": 1653318181387,
"timeLastUsed": 1653318181387,
"timePasswordChanged": 1653318181387,
"timesUsed": 1
},
{
"id": 6,
"hostname": "[https://pastebin.com](https://pastebin.com/)",
"httpRealm": null,
"formSubmitURL": "[https://pastebin.com](https://pastebin.com/)",
"usernameField": "",
"passwordField": "",
"encryptedUsername": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECLiLy66Hib5hBAiD7mnULqH9yg==",
"encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECHaK57PjFrnGBBgnnwQzS0WJL+4DuP7DJz0wFhRjSwMgXGA=",
"guid": "{10407907-e210-462d-ad4e-af89a55a4a7c}",
"encType": 1,
"timeCreated": 1653318394907,
"timeLastUsed": 1653318437524,
"timePasswordChanged": 1653318437524,
"timesUsed": 2
}
],
"potentiallyVulnerablePasswords": [],
"dismissedBreachAlertsByLoginGUID": {},
"version": 3
}
```

⚠️ **SPOILER ALERT** : You can directly Bruteforce the password by using BruteFox or firefox_decrypt (see links) but I didn’t find these tools during the CTF.

After several searches I saw that we could extract the hash of the master key and I found a script to do it (see mozilla2hashcat.py in **Links**).

By running the script we get this :

```bash
┌──(baddhack㉿kali)-[~/…/dump/Firefox/Profiles/nh7x18gj.default-release]
└─$ python [mozilla2hashcat.py](http://mozilla2hashcat.py/) key4.db
$mozilla$*AES*85d53a4628055f9e4cc1238fed092b5444b24eee*21af57842b20ac2bc38800d1c68f43bad2dcccb6fac2a36b870e36af92c56b21*10000*040ec632b9dc589c08217fad483f1354*9a8dee8e8bc13c177a45236cc944540e
```

Oh a wild hash appears ! 😮

Now we just have to look at what the hashcat documentation proposes for this type of hash…

> | 26100 |  Mozilla key4.db |
> 

It seems that it would be possible to perform a dictionnary attack on it 😄

So, I created a file **hash.txt** which contains the hash and started using hashcat.

```powershell
PS C:\Users\baddhack> .\hashcat.exe -m 26100 -a 0 -o cracked.txt hash.txt "C:\Users\baddhack\rockyou.txt"
hashcat (v6.2.5) starting

CUDA API (CUDA 11.7)
====================
* Device #1: NVIDIA GeForce RTX 3060 Ti, 7161/8191 MB, 38MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1470 MB

Dictionary cache built:
* Filename..: C:\Users\baddhack\rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 0 secs

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 26100 (Mozilla key4.db)
Hash.Target......: $mozilla$*AES*85d53a4628055f9e4cc1238fed092b5444b24...44540e
Time.Started.....: Mon Jun 06 14:44:44 2022 (2 secs)
Time.Estimated...: Mon Jun 06 14:44:46 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (C:\Users\baddhack\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   179.6 kH/s (10.91ms) @ Accel:16 Loops:64 Thr:512 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 311296/14344384 (2.17%)
Rejected.........: 0/311296 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9984-9999
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> desodorante
Hardware.Mon.#1..: Temp: 57c Fan:  0% Util: 99% Core:1963MHz Mem:6794MHz Bus:16

Started: Mon Jun 06 14:44:43 2022
Stopped: Mon Jun 06 14:44:47 2022

PS C:\Users\baddhack> .\hashcat.exe --show -m 26100 .\hash.txt
$mozilla$*AES*85d53a4628055f9e4cc1238fed092b5444b24eee*21af57842b20ac2bc38800d1c68f43bad2dcccb6fac2a36b870e36af92c56b21*10000*040ec632b9dc589c08217fad483f1354*9a8dee8e8bc13c177a45236cc944540e:fartknocker
```

**Firefox Master Key :** `fartknocker`

Someone else who uses a weak password …

Now we can use it to open the password manager. If you use Firefox, you can swap your **key4.db** and **logins.json** files in your profile with the two we have (make a backup if you personnaly use the manager) and access to the password manager graphically through the Firefox Browser.

Personnally I used **firefed**, which help you to inspect Firefox profiles with the command-line :

```bash
┌──(baddhack㉿kali)-[~/…/dump/Firefox/Profiles/nh7x18gj.default-release]
└─$ firefed -p ./ logins     
Master password: 

Host                         Username               Password               
---------------------------  ---------------------  -----------------------
https://fr-fr.facebook.com   pauljacquet@gmail.com  YjnHQKLSLPWO8566       
https://www.reddit.com       paul.jacqu3t           LKANSNHJSLPAMKncjfh8556
https://twitter.com          pauljacquet@gmail.com  A98zNbbJAKQLW10Q       
https://accounts.google.com  pauljacquet@gmail.com  MlnWJQIAhdtTZ42A589S   
https://pastebin.com         paul_jacquet           NSjjqnIAMSOAPD52698    
https://pastebin.com                                JnQKLWMpaoIEYGFNH5Q69Z
```

And here is the pastebin password 😄 : `JnQKLWMpaoIEYGFNH5Q69Z`

### Flag

`Hero{JnQKLWMpaoIEYGFNH5Q69Z}`

---

## Conclusion

This challenge was cool because it is directly related to a browser that many of you may use. The difficulty was not very high and there are tools to quickly get to the flag. However, I still wanted to write this document because I personally didn't directly find a tool to solve the challenge. I prefer to detail the steps in order to understand how Firefox works, what the manipulated files look like and why we proceeded this way to get the flag, rather than just giving a tool.

Thanks to the HeroCTF staff for all the other challenges, it was very cool and well organized.

---

## Links :

- [https://github.com/HeroCTF/HeroCTF_v4/tree/main/Forensics/MyPasswords](https://github.com/HeroCTF/HeroCTF_v4/tree/main/Forensics/MyPasswords)
- [https://github.com/L1ghtM4n/BruteFox](https://github.com/L1ghtM4n/BruteFox)
- [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)
- [https://github.com/numirias/firefed](https://github.com/numirias/firefed)
- [https://fossies.org/linux/hashcat/tools/mozilla2hashcat.py](https://fossies.org/linux/hashcat/tools/mozilla2hashcat.py)
- [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data)
