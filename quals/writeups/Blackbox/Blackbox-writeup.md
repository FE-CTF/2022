# FE-CTF 2022: Cyber Demon

# Challenge: Blackbox

For this challenge we're given a file (`file`) and the address
`blackbox.hack.fe-ctf.dk:1337`.

*Organizer's note:*

> This challenge was harder (more guessy) than intended.  We mistakenly
> redirected `stderr` to `/dev/null` instead of to the connected socket.
>
> In general we try to create challenges that do not rely (too much) on luck or
> guesswork.  If we host a similar event in the future, feel free to contact us
> if a challenge seems overly guessy.
>
> However, the challenge is still perfectly solvable; read on.

So what's in the file?

```
$ file file
file: data
```

OK...?

```
$ hexdump -C file
00000000  80 42 4d 8a 40 38 00 00  28 54 00 8a 29 7c 2a 05  |.BM.@8..(T..)|*.|
00000010  28 d0 82 02 28 01 00 20  00 03 2a 79 01 c3 0e 00  |(...(.. ..*y....|
00000020  e2 0a d4 ff 87 e9 d3 9b  42 47 52 73 17 df bf 77  |........BGRs...w|
00000030  2f 07 01 04 07 04 f0 5e  2a 12 ff e2 c6 87 47 8f  |/......^*.....G.|
00000040  07 07 07 01 6b 52 15 e2  ff c6 07 07 07 07 07 a7  |....kR..........|
00000050  67 e3 27 07 6b 52 15 e2  c6 07 7f 06 87 47 07 07  |g.'.kR.......G..|
00000060  07 01 33 fc 12 05 e2 c6  87 47 07 07 ff 07 07 07  |..3......G......|
00000070  07 07 07 07 07 ff 07 07  07 07 07 07 07 07 ff 07  |................|
00000080  07 07 07 07 07 07 07 ff  07 07 07 07 07 07 07 07  |................|
00000090  ff 07 07 07 07 07 07 07  07 ff 07 07 07 07 07 07  |................|
000000a0  07 07 ff 07 07 07 07 07  07 07 07 ff 07 07 07 07  |................|
[...]
```

The file is not complete randomness.  Notably we see `"BM"` and `"BGRs"` in
there which suggests this is really a BMP file mangled in some way.  But this
doesn't get us very far, so let's look at the remote service.

If we connect to the address with netcat then the connection just hangs there.
If we repeatedly type `<enter>` the connection is closed on the fifth key press:

```
$ nc blackbox.hack.fe-ctf.dk 1337
== proof-of-work: disabled ==
<enter>
<enter>
<enter>
<enter>
<enter>
$
```

*Organizer's note:*

> At this point we would have received the string `"size error"` had `stderr`
> not been redirected to `/dev/null`.

Experience tells us that one can never be sure exactly what `netcat` decides to
do or not do, so let's do that again programmatically.

**`recon0.py`:**

```.py
from pwn import *
sock = remote('blackbox.hack.fe-ctf.dk', 1337)
for i in iters.count(1):
    sock.send(b'\n')
    print(f'sent {i} bytes')
    print('>>>', sock.recv(timeout=1))
```

Running:

```
$ python recon0.py
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
sent 1 bytes
>>> b'== proof-of-work: disabled ==\n'
sent 2 bytes
>>> b''
sent 3 bytes
>>> b''
sent 4 bytes
Traceback (most recent call last):
  File "/home/user/recon0.py", line 6, in <module>
    print('>>>', sock.recv(timeout=1))
[...]
EOFError
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
```

OK, so we now know that the remote side actually closes the connection after four bytes has been sent.  Let's try enumerating four byte sequences and see what sticks:

**`recon1.py`:**

```.py
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
```

Running:

```
$ python recon1.py
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
sending b'\x00\x00\x00\x00'
sent 1 bytes
>>> b'== proof-of-work: disabled ==\n'
sent 2 bytes
>>> b''
sent 3 bytes
>>> b''
sent 4 bytes
connection closed
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
sending b'\x00\x00\x00\x01'
sent 1 bytes
>>> b'== proof-of-work: disabled ==\n'
sent 2 bytes
>>> b''
sent 3 bytes
>>> b''
sent 4 bytes
connection closed
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
sending b'\x00\x00\x00\x02'
sent 1 bytes
>>> b'== proof-of-work: disabled ==\n'
sent 2 bytes
>>> b''
sent 3 bytes
>>> b''
sent 4 bytes
connection closed
[...]
```

No difference at all.  Enumerating all four bytes combinations is going to take
some time, so let's be a little more clever about it.  Unless they (*organizer's
note:* we) really want us (*organizer's note:* you) to guess a random 4B cookie,
the value(s) that actually let's as talk to the service is probably going to be
"nice".  So we enumerate from different "corners" of the search space by
replaceing lines 15/16 with, respectively

```.py
for data in iters.combinations_with_replacement(
        reversed(range(256)), 4):
```

and

```.py
    test(bytes(reversed(data)))
```

Replacing only line 16 (`recon2.py`) gives us an interesting result:

```
$ python recon2.py
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
sending b'\x00\x00\x00\x00'
sent 1 bytes
>>> b'== proof-of-work: disabled ==\n'
sent 2 bytes
>>> b''
sent 3 bytes
>>> b''
sent 4 bytes
connection closed
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
sending b'\x01\x00\x00\x00'
sent 1 bytes
>>> b'== proof-of-work: disabled ==\n'
sent 2 bytes
>>> b''
sent 3 bytes
>>> b''
sent 4 bytes
>>> b''
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
sending b'\x02\x00\x00\x00'
sent 1 bytes
>>> b'== proof-of-work: disabled ==\n'
sent 2 bytes
>>> b''
sent 3 bytes
>>> b''
sent 4 bytes
>>> b''
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
```

Notice that in the last two cases the remote end does *not* close the
connection.

Hypothesis: the first four bytes encode a length field, little endian.  Let's test that hypothesis:

**`recon3.py`:**

```.py
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
            print('>>>', sock.recv(timeout=1))
        except EOFError:
            print('connection closed')
            print(f'successfully sent {realnumb} bytes')
            break
        sock.send(b'A')
    sock.close()
for numb in iters.count():
    test(numb)
```

Running:

```
$ python recon3.py
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
length = 0 bytes
sent 0 bytes
connection closed
successfully sent 0 bytes
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
length = 1 bytes
sent 0 bytes
>>> b''
sent 1 bytes
>>> b'\x00A'
sent 2 bytes
connection closed
successfully sent 2 bytes
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
length = 2 bytes
sent 0 bytes
>>> b''
sent 1 bytes
>>> b''
sent 2 bytes
>>> b'\x00AA'
sent 3 bytes
connection closed
successfully sent 3 bytes
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
length = 3 bytes
sent 0 bytes
>>> b''
sent 1 bytes
>>> b''
sent 2 bytes
>>> b''
sent 3 bytes
>>> b'\x00AAA'
sent 4 bytes
connection closed
successfully sent 4 bytes
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
length = 4 bytes
sent 0 bytes
>>> b''
sent 1 bytes
>>> b''
sent 2 bytes
>>> b''
sent 3 bytes
>>> b''
sent 4 bytes
>>> b'\x04AA\x00'
sent 5 bytes
connection closed
successfully sent 5 bytes
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[...]
```

So it looks like the service always sends some data after we've sent `numb`
bytes to it, then closes the connection on the next byte.  But the data that we
receive will make the `sock.recv` call return that data instead of raising
`EOFError`, so maybe our code is wrong.  Replace line 11 with (or see
`recon4.py`)

```.py
            while True:
                s = sock.recv(timeout=1)
                print('>>>', s)
                if not s:
                    break
```

Running again:

```
$ python recon4.py
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
length = 0 bytes
sent 0 bytes
connection closed
successfully sent 0 bytes
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
length = 1 bytes
sent 0 bytes
>>> b''
sent 1 bytes
>>> b'\x00A'
connection closed
successfully sent 1 bytes
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[+] Opening connection to blackbox.hack.fe-ctf.dk on port 1337: Done
length = 2 bytes
sent 0 bytes
>>> b''
sent 1 bytes
>>> b''
sent 2 bytes
>>> b'\x00AA'
connection closed
successfully sent 2 bytes
[*] Closed connection to blackbox.hack.fe-ctf.dk port 1337
[...]
```

Just as expected.  Now we're ready to start making some sense of the data that we receive.  Running `recon4.py` several times, we can see that the returned data is the same each time.  So presumable the remote service encodes or mangles our data in some way.  Let's encapsulate that in a function:

**`encode.py`:**

```.py
from pwn import *
def encode(data):
    with context.silent:
        sock = remote('blackbox.hack.fe-ctf.dk', 1337)
        # Read "proof-of-work" line
        sock.recvline()
        sock.send(p32(len(data)))
        sock.send(data)
        return sock.recvall()
```

As is tradition we now throw "`A`"s at it (`send-As.py`):

```
$ python send-As.py
Input : 41 length 1
Output: 0041
Input : 4141 length 2
Output: 004141
Input : 414141 length 3
Output: 00414141
Input : 41414141 length 4
Output: 04414100
Input : 4141414141 length 5
Output: 0441410041
Input : 414141414141 length 6
Output: 0c41410000
Input : 41414141414141 length 7
Output: 0c41410001
Input : 4141414141414141 length 8
Output: 0c41410002
Input : 414141414141414141 length 9
Output: 0c4141000241
Input : 41414141414141414141 length 10
Output: 1c4141000200
Input : 4141414141414141414141 length 11
Output: 1c4141000201
[...]
```

For 1-3 "`A`"s we just get the same data back with a zero in front.  But for
longer sequences interesting things start to happen.  Four and five `"A"`s are
encoded identically except the latter has an extra `"A"` at the end.  A keen eye
will see that the first byte, 4, has exactly the third bit set and the third
following byte is *not* an `"A"`.

We observe the same pattern at lengths six and ten, which have a first byte of
12 (`0b00001100`) and 28 (`0b00011100`).  Here we again see that the following
bytes with an index corresponding to a 1-bit are *not* `"A"`s.

So a working hypothesis is: every ninth byte is a header which tells us which of
the following 8 bytes are raw data and which are encoded (in some way).

Throwing a bunch more `"A"` at it confirms (or does not deny, at least) this
hypothesis:

```
$ python send-As.py
[...]
Input : 41[...] length 43
Output: fc4141000206070707
Input : 41[...] length 44
Output: fc41410002060707070041
Input : 41[...] length 45
Output: fc41410002060707070100
[...]
```

In the last two lines we see the raw `"A"` switch to an "encoding byte" which
is 0.  We can also conclude that this 0 means `"AA"`.

Assumption: Internally the service has a codebook mapping encoded bytes to
codewords.  This means that the codebook can have at most 256 entries.  So the
question now is: where does this codebook come from?, and if it is build from
the encoded data, how?

Switching from sending `"A"`s to sending `"B"`s we see the same pattern:

```
$ python send-Bs.py
[...]
Input : 42[...] length 44
Output: fc42420002060707070042
Input : 42[...] length 45
Output: fc42420002060707070100
```

So we conclude that the codebook is build from the encoded data itself, which
also fits with the fact that `"AAA"` is encoded as all raw bytes.  We also see
that the encoding is shorter than the raw data (at least for `"A"`s), so
presumably we're dealing with some sort of compression.

*Organizer's note:*

> Those of you who recognize an LZSS-like scheme can skip to the end now.

To make testing easier we create yet another script (`encode-interactive.py`):

```.py
from encode import encode
while True:
    idat = input('> ').strip().encode()
    odat = encode(idat)
    print('Input :', idat.hex(), 'length', len(idat))
    print('Output:', odat.hex())
```

Toying around a bit we observe something surprising:

```
$ python encode-interactive.py
> AAABAB
Input : 414141424142 length 6
Output: 104141414210
```

How could the codebook have 16 entries already?  We know that the codebook does
not have 1-byte entries and `"AAAB"` only has five unique substrings of length
at least two.  Enumerating the other four substrings we get:

```
> AAABAA
Input : 414141424141 length 6
Output: 104141414200
> AAABAAA
Input : 41414142414141 length 7
Output: 104141414201
> AAABAAB
Input : 41414142414142 length 7
Output: 104141414209
> AAABAAAB
Input : 4141414241414142 length 8
Output: 104141414202
```

If we split the encoding byte into two parts of three and five bits we can
re-interpret our findings thus:

```
(AAAB)AA   -> (0, 0) # 0x00 = 0b00000_000
(AAAB)AAA  -> (1, 0) # 0x01 = 0b00000_001
(AAAB)AAAB -> (2, 0) # 0x02 = 0b00000_010
(AAAB)AAB  -> (1, 1) # 0x09 = 0b00001_001
(AAAB)AB   -> (0, 2) # 0x10 = 0b00010_000
```

Now it looks a lot like a length and an index.  So maybe there's not even a
codebook after all?  Reiterating, `"AAABAAB"` must be encoded as

- Header for (up to) next 8 bytes
- Raw `"A"`
- Raw `"A"`
- Raw `"A"`
- Raw `"B"`
- 1 + 2 = 3 bytes starting at index 1: `"AAB"`

This means that the largest index that can be encoded is 2^5 = 32.  Since that
would prohibit the service from compressing larger files the index is probably
really an index into a window.  We can easily test that hypothesis:

```
$ python encode-interactive.py
> B[...]AAAA
Input : 42[...]41414141 length 33
Output: 7c42420002060702410241e8
> B[...]BAAAA
Input : 42[...]4241414141 length 34
Output: 7c42420002060703410241f0
> B[...]BBAAAA
Input : 42[...]424241414141 length 35
Output: 7c42420002060704410241f0
```

We note that with this scheme the index field can never be larger than 30, which
suggests our hypothesis is not 100% correct yet.  Regardless we can implement
our current model and test it against the remote service.

**`model.py`:**

```.py
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
```

Running:

```
$ python model.py
OK (1)
[...]
OK (9001)
```

IT'S OVER 9000! So we declare the model correct.

Now writing the decoder is not too difficult.

**`decode.py`:**

```.py
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
```

Running:

```
$ python decode.py
OK (1)
OK (2)
[...]
```

Great.  Now only one question remains: what should we decode?  Let's take that file we got with the challenge for a spin:

```
$ python -c "import decode ; open('file.bmp', 'wb')"\
".write(decode.decode_model(open('file', 'rb').read()))"
```

![](file.bmp)
