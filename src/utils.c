#include <stdio.h>
#include "arpspoof.h"

void show_mem(void *ptr, size_t len)
{
    printf("Memory:");
    for (size_t i = 0; i < len; i++)
    {
        if (i % 4 == 0)
            printf("\n%d\t%p\t", (int)i, ptr + i);
        printf(" %.2x", *((unsigned char *)ptr + i));
    }
    printf("\n\n");
}

int is_big_endian()
{
    union {
        uint32_t i;
        char c[4];
    } e = {0x01000000};

    return e.c[0];
}
