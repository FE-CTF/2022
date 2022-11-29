from encode import encode
while True:
    idat = input('> ').strip().encode()
    odat = encode(idat)
    print('Input :', idat.hex(), 'length', len(idat))
    print('Output:', odat.hex())
