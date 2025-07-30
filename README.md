# 💉 Process Injection Techniques

This repository contains a collection of classic and modern payload injection techniques, commonly used in malware development, red teaming, and post-exploitation. The goal is to provide clean, understandable examples for educational and research purposes.

> ⚠️ **Disclaimer:** This project is for **educational** purposes only. The author does **not condone** or support any malicious or illegal activity. Use responsibly in lab environments only.

---

## 📌 Description

Payload injection is a technique used to execute arbitrary code in the context of another process. This is a core part of offensive operations, post-exploitation, and malware behavior. The examples in this repository demonstrate how attackers inject DLLs or obfuscated shellcode into remote processes using Windows API functions.

*The repo currently includes*:

- **Remote Dll Injection**
- **Remote Shellcode Injection**

## 🧰 Features

- Lightweight and simple C implementations.
- Can be easily integrated into other malware or red team projects.
- Helps blue teams understand how process injection is done in the wild.

 
## Getting Started
1. Clone the repository:

```bash
    git clone https://github.com/Zanebilal/ProcessInjectionTechniques
```
2.  Navigate to the desired technique folder and compile: 

```bash
    cd /RemoteDllInjection/RemoteDllInjection/remoteDllInjection.c
    gcc remoteDllInjection.c -o remoteDllInjection
 ```
