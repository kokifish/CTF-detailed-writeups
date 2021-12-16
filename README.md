# CTF-detailed-writeups

<p>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="updated time" src="https://badges.pufler.dev/updated/hex-16/CTF-detailed-writeups"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="created time" src="https://badges.pufler.dev/created/hex-16/CTF-detailed-writeups"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="commits" src="https://badges.pufler.dev/commits/monthly/hex-16"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="visits" src="https://badges.pufler.dev/visits/hex-16/CTF-detailed-writeups"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="GitHub repo file count (file type)" src="https://img.shields.io/github/directory-file-count/hex-16/CTF-detailed-writeups?style=flat-square&type=file"></a>
</p>


Very detailed CTF writeups. Try to make it understandable to CTF beginners. Bilingual in Chinese and English, mainly in Chinese.中英双语 中文为主

This REPO is devoted to writing very detailed writeups so that CTF beginners (including me) can replicate the resolution process. 本repo致力于写十分详细的writeup，让CTF beginners也能复现解题过程。~~也可能因为懒，部分writeup会写的比较简洁~~

Some CTF notes will also be saved under this REPO. 部分CTF相关笔记也会保存在此repo下

# Norm

- **Avoid** using **Chinese file/directory names**. Otherwise it may cause some problems in some system environment.
- **Avoid** using **complex file structure** in a challenge folder. Put all the related files in the **same directory** if not too many.
- Write down the **English** version of proper word. This will make it easier to Google.
- Write down the **challenge description** and **original/refer writeup** (if refer to someone else's work) at the beginning of writeup.
- List **environment requirements** if it is specific or not commonly used. Some commonly used environment: latest `python3`, `c++11`,`gcc`, `make`, and other commonly used tools in CTF

## Challenge Naming Conventions

- level-1 directory: **challenge class**. Mainly includes crypto, web, reverse, misc, pwn, etc
- level-2 directory: **challenge sub class, game name, year, [sub game name], challenge name**, separated by underscore.
  - **Format**: `challenge_sub_class_game_name_year_challenge_name`, here are some examples:
  - `image_analysis_breakin_ctf_2017_Mysterious_GIF`, here `image_analysis` is challenge sub class
  - `forensic_and_info_retrieval_xctf_2020_huaweictf_s34hunka`, here `huaweictf` is sub game name
  - `image_analysis_zongheng_2020_mosaic`
- `[alt]` level-3 directory: `pic`, `src`, `doc`,`test`, etc. But **avoid** using it. Use the full name is permitted.

> Archive simple/similar cases in a folder named by `challenge_subclass`, e.g. `Heap_OffByOne`

# Contacts

new an issue or email: [hexhex16@outlook.com](mailto:hexhex16@outlook.com)

We welcome to write content for the repo and share your writeup.

# Copyright

The copyright of original content belongs to the corresponding contributors under this repo. We will try to indicate the source of other content.



---

# Resources

updating

- https://ctftime.org/event/list/upcoming   upcoming CTF
- https://github.com/firmianay/CTF-All-In-One   CTF竞赛权威指南
- https://github.com/ctf-wiki/ctf-wiki  https://ctf-wiki.org/  for beginners
- https://github.com/MOCSCTF/CTF-Write-UP
- https://github.com/ctfs/write-ups-2017
- https://adworld.xctf.org.cn/ 含wp的刷题
- https://www.ichunqiu.com/
- https://www.bugbank.cn/
- https://blog.knownsec.com/Knownsec_RD_Checklist/index.html 
- https://github.com/CHYbeta/Web-Security-Learning   web
- https://github.com/CHYbeta/Software-Security-Learning  pwn
- https://github.com/Audi-1/sqli-labs sqli challenges
- https://buuoj.cn/ 纯刷题
- http://ww1.viristotal.com/
- https://cryptohack.org/   crypto刷题

