# UYBHYS-2019-Pouply

A great event, many thanks to the organizers and sponsors !

@pentest_swissky has made a [write-up](https://swisskyrepo.github.io/SeaMonsterCTF/). In this part, we will cover some parts not coverted by his write-up, namely two custom services deployed on `bastion` host, running on `tcp/4141` and `tcp/4242`.

# bastion.unlock.ctf:4242

Roughly 200 lines of unobfuscated C code.

Staring at the code, use of `malloc`, `free`, and a while true loop to make actions.

At the top of the file are two structures:

```
struct Livre {
    char nom[12];
    void (*Lire)();
    void (*TheFlag)();
    void (*Preter)(struct Livre*);
};

struct Bibliotheque {
    char address[16];
    char nom[8];
};
```

Looking back at the clues:

* `malloc` and `free` in a while true loop
* two structures of the same size, `24` bytes
* a set of function pointers in one of the structure

Just sounds like a perfect match for **use after free**.

Taking a look at `free` calls, we see that while the memory is freed, the pointer itself is not set to `NULL` after freeing it. We might have dangling pointers left, we could abuse to call `TheFlag` function using a pointer.

The plan is to make the following calls:

1. `livre = malloc(24)`. Fill livre with garbage, we don't care. 
2. `free(livre)`. **livre is not set to NULL**.
3. `bibli = malloc(24)`. **Got the same pointer as just before, livre == bibli**. Fill `bibli` with interesting values, such as `pwn.util.cyclic.cyclic(n=4)`.
4. `livre->Lire();`. Based on the structure layouts, `Lire` field will be aliased with the four last bytes of bibli `address` field. **Just have to set them to `TheFlag` address to get the flag**

Repeat the operation, now setting the `bibli` fields to the correct value to leak the flag, and get rich =)

# bastion.unlock.ctf:4141

Roughly 100 line of clean C code.

A tcp server, forking to process clients
