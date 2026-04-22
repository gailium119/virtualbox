// lshrdi3.c
#include <stdint.h>
#ifdef __clang__
uint64_t __lshrdi3(uint64_t a, int b)
{
    if (b == 0)
        return a;
    if (b >= 64)
        return 0;
    unsigned int hi = (unsigned int)(a >> 32);
    unsigned int lo = (unsigned int)a;
    if (b >= 32) {
        return (uint64_t)(hi >> (b - 32));
    } else {
        unsigned int new_hi = hi >> b;
        unsigned int new_lo = (hi << (32 - b)) | (lo >> b);
        return ((uint64_t)new_hi << 32) | new_lo;
    }
}
#endif