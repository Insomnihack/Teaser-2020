#!/usr/bin/env python3
from pwn import *
import r2pipe

# Generate the shellcode
context.update({'arch':'i386', 'bits':32, 'endian':'little'})
new_EP = 0x46f0a8
original_EP = 0x46e350
diff_start = 0x46d1a7
diff_len = 0x11a1

shellcode = asm('''
pushad                 # 1. Parse the PE header and get the base address of kernel32.dll in ebx
xor ecx, ecx           
mov eax, fs:[ecx+0x30]
mov eax, [eax+0xc]
mov esi, [eax+0x14]
lodsd
xchg eax, esi
lodsd
mov ebx, [eax+0x10]    # ebx = kernel32.dll base address



mov edx, [ebx+0x3c]    # 2. Get the address of kernel32.GetCommandLineA in edx
add edx, ebx
mov edx, [edx+0x78]
add edx, ebx
mov esi, [edx+0x20]
add esi, ebx
xor ecx, ecx
findGetCommandLineA:
inc ecx
lodsd
add eax, ebx
cmp dword ptr [eax], 0x43746547
jne findGetCommandLineA
cmp dword ptr [eax+0x4], 0x616d6d6f
jne findGetCommandLineA
cmp dword ptr [eax+0x8], 0x694c646e
jne findGetCommandLineA
cmp dword ptr [eax+0xc], 0x0041656e
jne findGetCommandLineA
mov esi, [edx+0x24]
add esi, ebx
mov cx, [esi+ecx*2]
dec ecx
mov esi, [edx+0x1c]
add esi, ebx
mov edx, [esi+ecx*4]
add edx, ebx           # edx = kernel32.GetCommandLineA



call edx               # 3. Test the value of the end of the command line (the last argument)
jmp beginSearchLastArg
loopSearchLastArg:
inc eax
beginSearchLastArg:
cmp byte ptr [eax], 0x00
jnz loopSearchLastArg

push 0x00
push 0x33e377fd
push 0xd7831bba
push 0x4ce1b463
push 0x42
pop ecx

testArg:
xor edx,edx
dec eax
add cl, byte ptr [eax]
cmp cl, byte ptr[esp]
je testOk        
or dl,1 # test fail
testOk:
inc esp
cmp byte ptr [esp], 0x00
jnz testArg              

pop ecx
cmp dl,0
jne jumpToOEP        # If the test fails, do nothing and return to OEP, get JEBAITED

decode:               # If you did not get JEBAITED, decode the original binary
mov al, byte ptr [originalBinary + ecx]
mov byte ptr [{} + ecx], al
mov byte ptr [originalBinary + ecx], 0x0
inc ecx
cmp ecx, {}
jb decode

jumpToOEP:
jmp {}

originalBinary:
'''.format(diff_start, diff_len, original_EP+1), vma=new_EP)

# Read the compressed code from the original file

diff_file = 'diff.bin'

r2 = r2pipe.open('kaboom_real_flag.exe')
r2.cmd('s {}'.format(diff_start))
r2.cmd('wtf {} {}'.format(diff_file, diff_len))
r2.quit()

# Patch the kaboom file

print(disasm(shellcode, vma=new_EP))

r2 = r2pipe.open('kaboom_jebaited.exe', flags=['-w']) # Open file in write mode
r2.cmd('s {}'.format(new_EP))                # Seek to the new entry point
r2.cmd('wxs {}'.format(enhex(shellcode)))    # Write the shellcode and seek to the end
r2.cmd('wff {}'.format(diff_file))           # Write the original compressed binary
r2.quit()