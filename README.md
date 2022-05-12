# CTF-detailed-writeups

<p>
<a href="https://github.com/hex-16/CTF-detailed-writeups/star"><img alt="stars" src="https://img.shields.io/github/stars/hex-16/CTF-detailed-writeups?style=social"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="watchers" src="https://img.shields.io/github/watchers/hex-16/CTF-detailed-writeups?style=social"></a> 
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="updated time" src="https://badges.pufler.dev/updated/hex-16/CTF-detailed-writeups"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="last-commit" src="https://img.shields.io/github/last-commit/hex-16/CTF-detailed-writeups"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="created time" src="https://badges.pufler.dev/created/hex-16/CTF-detailed-writeups"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="visits" src="https://badges.pufler.dev/visits/hex-16/CTF-detailed-writeups"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups"><img alt="license" src="https://img.shields.io/github/license/hex-16/CTF-detailed-writeups"></a>
<a href="https://github.com/hex-16/CTF-detailed-writeups/graphs/commit-activity"><img alt="maintained" src="https://img.shields.io/badge/Maintained%3F-yes-green.svg"></a>
</p>

Very detailed CTF writeups. Try to make it understandable to CTF beginners. 

Languages: Bilingual in Chinese and English, mainly in Chinese.中英双语 中文为主

This REPO is devoted to writing very detailed writeups so that CTF beginners (including me) can replicate the resolution process. 本repo致力于写十分详细的writeup，让CTF beginners也能复现解题过程。~~也可能因为懒，部分writeup会写的比较简洁~~

Some CTF notes will also be saved under this REPO. 部分CTF相关笔记也会保存在此repo下

# Norm

- **Avoid** using **Chinese file/directory names**. Otherwise it may cause some problems in some system environment.
- **Avoid** using **complex file structure** in a challenge folder. Put all the related files in the **same directory** if not too many/big.
- Write down the **English** version of proper word. This will make it easier to Google.
- Write down the **challenge description** and **original/refer writeup** (if refer to someone else's work) at the beginning of writeup.
- List **environment requirements** if it is specific or not commonly used. Some commonly used environment: latest `python3`, `c++11`,`gcc`, `make`, and other commonly used tools in CTF.

## Challenge Naming Conventions

- level-1 directory: **challenge class**. Mainly includes android, crypto, web, reverse, misc, pwn, reverse, etc
- level-2 directory(single chall): **challenge sub class, game name, year, [sub game name], challenge name**, separated by underscore.
  - **Format**: `challenge_sub_class_game_name_year_challenge_name`, here are some examples:
  - `image_analysis_breakin_ctf_2017_Mysterious_GIF`, here `image_analysis` is challenge sub class
  - `forensic_and_info_retrieval_xctf_2020_huaweictf_s34hunka`, here `huaweictf` is sub game name
  - `image_analysis_zongheng_2020_mosaic`
- level-2 directory(multi chall): **year_game_name_chall_names**, e.g.
  - `2022_starCTF_simplefs_NaCl`

- `[alt]` level-3 directory: `pic`, `src`, `doc`,`test`, etc. But **avoid** using it. Use the full name is permitted.

> Archive simple/similar cases in a folder named by `challenge_subclass, [SimpleCases]_`, e.g. `Heap_OffByOne`, `[SimpleCases]_ROP`

# Contacts

new an issue or make a pull request

We welcome to write content for the repo and share your writeup.

# Copyright

The copyright of original content belongs to the corresponding contributors under this repo. We will try to indicate the source of other content.



---

# Resources

updating

- https://ctftime.org/event/list/upcoming   upcoming CTF
- https://github.com/firmianay/CTF-All-In-One   CTF竞赛权威指南
- https://github.com/ctf-wiki/ctf-wiki    https://ctf-wiki.org/  for beginners
- https://adworld.xctf.org.cn/  含wp的刷题
- https://www.ichunqiu.com/   i春秋
- https://www.bugbank.cn/   
- https://blog.knownsec.com/Knownsec_RD_Checklist/index.html 
- https://github.com/CHYbeta/Web-Security-Learning   web
- https://github.com/CHYbeta/Software-Security-Learning  pwn
- https://github.com/Audi-1/sqli-labs sqli challenges
- https://buuoj.cn/ 纯刷题
- http://ww1.viristotal.com/
- https://cryptohack.org/   crypto刷题
- https://gchq.github.io/CyberChef/  CyberChef many tools
- https://ctf.pediy.com/itembank.htm 看雪CTF题库
- https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN  Binary Exploitation / Memory Corruption by LiveOverflow

