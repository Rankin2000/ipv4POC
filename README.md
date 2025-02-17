IPV4 Proof-of-concept Tool developed as part of https://stuartrankin.uk/ipv4-obfuscation-of-shellcode-a-technique-used-by-threat-groups-like-hive/

Takes msfvenom hex and output C file containing shellcode obfuscated as IPv4 addresses, Deobfuscation function and basic shellcode runner via Thread Hijacking.

Usage: msfvenom -p windows/x64/exec CMD="calc.exe" | python ipv4.py -o calc.c

Build .c file in Visual Studio
