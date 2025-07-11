static __inline void copy_char_array_16(unsigned char dst[16], const unsigned char src[16])
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++)
    {
        dst[i] = src[i];
    }
}
