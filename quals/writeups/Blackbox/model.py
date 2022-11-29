OFFSET_BITS = 5
LENGTH_BITS = 3
WINDOW_SIZE = 2**OFFSET_BITS
MIN_LENGTH = 2
MAX_LENGTH = MIN_LENGTH + 2**LENGTH_BITS - 1
def encode_model(idat):
    odat = bytearray()
    i = 0
    while i < len(idat):
        if len(odat) % 9 == 0:
            # Record index of header, which is constructed below
            hdridx = len(odat)
            odat.append(0)
        # Start of window
        window = max(0, i - WINDOW_SIZE)
        best_length = 0
        best_offset = offset = 0
        # Iterate over offsets into window
        while window + offset < i:
            # Iterate over lengths
            length = 0
            while True:
                k = i + length
                l = window + offset + length
                if length >= MAX_LENGTH:
                    break
                if k >= len(idat):
                    break
                if l >= i:
                    break
                if idat[l] != idat[k]:
                    break
                length += 1
            if length > best_length:
                best_length = length
                best_offset = offset
            offset += 1
        length = best_length
        offset = best_offset
        if length >= MIN_LENGTH:
            # Patch a 1-bit into header
            odat[hdridx] |= 1 << (len(odat) % 9 - 1)
            # Encode this chunk as a reference
            hdr = (offset << LENGTH_BITS) | (length - MIN_LENGTH)
            odat.append(hdr)
            i += length
        else:
            # Encode raw byte
            odat.append(idat[i])
            i += 1
    return odat

def test():
    import os
    import sys
    import random
    from itertools import count
    from encode import encode as encode_pukka
    for n in count(1):
        ilen = random.randrange(0, 0x1000)
        idat = os.urandom(ilen)
        odat_model = encode_model(idat)
        odat_pukka = encode_pukka(idat)
        if odat_pukka != odat_model:
            print('Found counter example')
            print('Input:', idat.hex())
            print('Pukka output:', odat_pukka.hex())
            print('Model output:', odat_model.hex())
            sys.exit(1)
        else:
            print(f'OK ({n})')

if __name__ == '__main__':
    test()
