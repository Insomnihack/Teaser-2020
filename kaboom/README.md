# Kaboom

## Description

- **Event**: Insomni'hack 2020 teaser
- **Category**: Reverse engineering
- **Points**: 94
- **Solves**: 57
- **Author**: remmer

This challenge was meant to be a simple RE challenge, not too challenging. No anti-debug, no obfuscation, no nothing!

## How to solve

The main trick was to not blindly use `upx -d` to unpack the binary, as this would result in a "jebaited" version that doesn't even have the flag. How to figure this out? There were many different ways:

- try to repack the unpacked binary and notice that the size is smaller than the original... *weird*
- notice that there are two occurrences of the string `INS` that seem very similar but not really... the first one is followed by the troll YouTube link and the second one looks much more like a real flag: `INS\x8d$\xfe{\xcc\x0fGG EZra\xff\x15\x89\xffp PogU 5H\x10B) Krey\xe9?\xd6\xfegasm <3\x02}` *weird*
- try to compare the packed binary with another packed binary of your choosing and notice that:
  - the UPX2 section should not be executable... *weird*
  - the first few instructions do not match... *weird*
- reverse the jebaited version until you are confident enough that it doesn't actually have the flag

Instead on unpacking, you just had to set a breakpoint at very first instruction of the original binary and reverse the few lines of assembly.

- Short solution: just patch the condition after the result of `GetCommandLineA` is checked and invert it. Then you can call the binary with whatever second argument and it will print the flag e.g. `.\kaboom.exe defuse foobar`

- Slightly longer (maybe 2 minutes more?) solution: reverse the part that checks the command line and notice that it expects it to end with `Plz&Thank-Q!`, then run `.\kaboom.exe defuse Plz&Thank-Q!` (escape the `&` if needed).

That's it.

## How it works

### Source code

The original source code is very short and simple:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFUSE "defuse"
#define FLAG   "https://www.youtube.com/watch?v=oGJr5N2lgsQ"
#define CANARY "INS{"
#define KABOOM "KABOOM!\n"

int main(int argc, char *argv[])
{

    if (   (argc < 2)
        || (strcmp(argv[1], DEFUSE) != 0)
        || (memcmp(CANARY, FLAG, strlen(CANARY)) != 0)
       )
    {
        printf("%s", KABOOM);
        return EXIT_FAILURE;
    }

    printf("Congrats! The flag is %s\n", FLAG);
    return EXIT_SUCCESS;
}
```

It just checks that the first command line argument is "defuse" and that the flag starts with the correct format `INS{`. If one of these conditions is false, it prints `KABOOM!`, otherwise it prints the flag. In this case, the second condition is always false so it always explodes.

### Jebaited vs real flag version

I compiled the code statically as `kaboom_jebaited.exe` because as you can see, there is no flag for now but only a troll jebaited song.

Then, I copied the compiled binary and replaced the occurrences of the fake flag by the real flag with the correct format `INS{...}`, and I named this one `kaboom_real_flag.exe`.

Using `radiff2`, I determined the areas of the two files that are not the same.

### Prepping the binary before patching

Using a PE editor, I increased the size of the section `UPX2` and set it as executable. I also disabled PIE to make my life easier (use hardcoded addresses in my backdoor). I added some null bytes at the end of the file to create a code cave, and I changed the address of the entry point to point at the beginning of my code cave.

### Simple "backdoor"

The script [kaboom_patch.py](./kaboom_patch.py) patches `kaboom_jebaited.exe`. Please don't judge, it was not meant to be beautiful! Also I am aware that the term "shellcode" is not technically correct in this case.

What it does is pretty simple:

- Dump the bytes from `kaboom_real_flag.exe` that are different from the original version in a file `diff.bin`
- Write a small "shellcode" in the code cave which:
  - Resolves the address of `GetCommandLineA` and calls it
  - Checks if the command line ends with `Plz&Thank-Q!`
  - If this condition is true, re-writes in memory the content from `diff.bin` instead of the original jebaited version
  - Jumps to the original entry point of the unpacking
- Write the content of the `diff.bin` file right after that

That's it! Hope you had fun :)
