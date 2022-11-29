from encode import encode
from itertools import count
for n in count(1):
    idat = b'A' * n
    odat = encode(idat)
    print('Input :', idat.hex(), 'length', len(idat))
    print('Output:', odat.hex())
