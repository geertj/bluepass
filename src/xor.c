typedef unsigned char u8;
typedef unsigned long long u64;

int crypto_xor(u8 *c, u8 *m, u64 mlen, u8 *k)
{
    u64 i;

    for (i=0; i<mlen; i++)
        c[i] = m[i] ^ k[i];

    return 0;
}
