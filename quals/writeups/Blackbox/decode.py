OFFSET_BITS = 5
LENGTH_BITS = 3
WINDOW_SIZE = 2**OFFSET_BITS
MIN_LENGTH = 2
MAX_LENGTH = MIN_LENGTH + 2**LENGTH_BITS - 1
def decode_model(idat):
    odat = bytearray()
    i = 0
    while i < len(idat):
        hdr = idat[i]
        i += 1
        for _ in range(8):
            if hdr & 1:
                # Decode referenced chunk
                pair = idat[i]
                length = (pair & (2**LENGTH_BITS - 1)) + MIN_LENGTH
                offset = pair >> LENGTH_BITS
                window = max(0, len(odat) - WINDOW_SIZE)
                chunk = odat[window + offset : window + offset + length]
                odat.extend(chunk)
            else:
                # Raw byte
                odat.append(idat[i])
            i += 1
            # End of data?
            if i >= len(idat):
                break
            # Next header bit
            hdr >>= 1
    return odat

def test():
    import os
    import sys
    import random
    from itertools import count
    from model import encode_model
    for n in count(1):
        ilen = random.randrange(0, 0x1000)
        idat = os.urandom(ilen)
        odat = encode_model(idat)
        idat2 = decode_model(odat)
        if idat != idat2:
            print('Found counter example')
            print('Input  :', idat.hex())
            print('Output :', odat.hex())
            print('Decoded:', idat2.hex())
            sys.exit(1)
        else:
            print(f'OK ({n})')

if __name__ == '__main__':
    test()
