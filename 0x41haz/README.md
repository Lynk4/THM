# 0x41haz
---

In this challenge, you are asked to solve a simple reversing solution. Download and analyze the binary to discover the password.

A executable file is provided.

when checking it's file types it gives an error message for os ***unknown arch 0x3e00* (SYSV)**
googling it gives me a solution **you need to patch the sixth byte (0x02) to 0x01.**


**FROM THIS**
---
<img width="1266" alt="Screenshot 2024-03-27 at 8 39 38 PM" src="https://github.com/Lynk4/THM/assets/44930131/f82ce45d-e34e-4837-866d-55558a69b4a4">

---
**TO THIS**

<img width="1271" alt="Screenshot 2024-03-27 at 8 38 51 PM" src="https://github.com/Lynk4/THM/assets/44930131/e1e7fdc0-ee0d-4f94-a260-b61c74098e1c">

---

<img width="1282" alt="Screenshot 2024-03-27 at 8 37 15 PM" src="https://github.com/Lynk4/THM/assets/44930131/5b003ca6-a577-4246-8229-eeb438ae9276">

---

AFTER THAT execute it

<img width="617" alt="Screenshot 2024-03-27 at 8 43 17 PM" src="https://github.com/Lynk4/THM/assets/44930131/3f2b0b8d-4d5a-4a4a-b322-a9fce3ba4bf2">

asking for a password..


### Now open it in radare2 to analyze it...

By analyzing the main function you will get the password:

---
<img width="1296" alt="Screenshot 2024-03-27 at 8 29 22 PM" src="https://github.com/Lynk4/THM/assets/44930131/1db974e8-d77b-4fbe-98e4-8e9a2b08690b">


---

password:
```
2@@25$gfsT&@L
```


flag:
```
THM{2@@25$gfsT&@L}
```
---

