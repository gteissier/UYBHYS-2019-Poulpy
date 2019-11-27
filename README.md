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

Looking back at the clues:

* `malloc` and `free` in a while true loop
* two structures of the same size, `24`
* function pointers

It is a perfect match for **use after free**.

Taking a look at `free` calls, we see that while the memory is freed, the pointer itself is not set to `NULL` after freeing it. We might have dangling pointers left, we could abuse.



# bastion.unlock.ctf:4141

Roughly 100 line of clean C code.

A tcp server, forking to process clients
