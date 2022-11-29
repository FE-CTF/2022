from pwn import *
def test(data):
    sock = remote('blackbox.hack.fe-ctf.dk', 1337)
    print(f'sending {data}')
    for i, b in enumerate(data, start=1):
        sock.send(bytes([b]))
        print(f'sent {i} bytes')
        try:
            print('>>>', sock.recv(timeout=1))
        except EOFError:
            print('connection closed')
            break
    sock.close()

for data in iters.combinations_with_replacement(range(256), 4):
    test(bytes(data))
