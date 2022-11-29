from pwn import *
sock = remote('blackbox.hack.fe-ctf.dk', 1337)
for i in iters.count(1):
    sock.send(b'\n')
    print(f'sent {i} bytes')
    print('>>>', sock.recv(timeout=1))
