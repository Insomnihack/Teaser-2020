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