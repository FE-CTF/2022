from pwn import *
def encode(data):
    with context.silent:
        sock = remote('blackbox.hack.fe-ctf.dk', 1337)
        # Read "proof-of-work" line
        sock.recvline()
        sock.send(p32(len(data)))
        sock.send(data)
        return sock.recvall()
