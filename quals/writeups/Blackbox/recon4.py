from pwn import *
def test(numb):
    sock = remote('blackbox.hack.fe-ctf.dk', 1337)
    # Read "proof-of-work" line
    sock.recvline()
    print(f'length = {numb} bytes')
    sock.send(p32(numb))
    for realnumb in iters.count():
        print(f'sent {realnumb} bytes')
        try:
            while True:
                s = sock.recv(timeout=1)
                print('>>>', s)
                if not s:
                    break
        except EOFError:
            print('connection closed')
            print(f'successfully sent {realnumb} bytes')
            break
        sock.send(b'A')
    sock.close()
for numb in iters.count():
    test(numb)
