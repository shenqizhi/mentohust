#include "md5forvz.h"
#include "ripemd.h"
#include "sha1.h"
#include "tiger.h"
#include "whirlpool.h"
#include "../types.h"
static BYTE *bin_8021x = NULL;
static DWORD size_8021x;
static BYTE *bin_w32n55 = NULL;
static DWORD size_w32n55;
static BYTE hex[][17]={"0123456789ABCDEF", "0123456789abcdef"};

void RipeFile(void* out, void* in, DWORD size)
{
    RIPEMD_CTX s;
    RipemdInit(&s);
    BYTE *p;
    int i;
    p = in;
    for (i=0; i<size/64; i++)
    {
        RipemdUpdate(&s, p, 64, size);
        p+=64;
    }
    RipemdUpdate(&s, p, size % 64, size);
    memcpy(out, &s.state[0], 16);
}

void TigerFile(void* out, void* in, DWORD size)
{
    TIGER_CTX s;
    TIGER_Init(&s);
    BYTE *p;
    int i;
    p = in;
    for (i=0; i<size/64; i++)
    {
        TIGER_Update(&s, p, 64, size);
        p+=64;
    }
    TIGER_Update(&s, p, size % 64, size);
    memcpy(out, &s.state[0], 24);
}

void hex_to_str_buf(const BYTE *a, void *out, int hexsize, int upper) {
    BYTE *q = (BYTE *)out;
    int i;
    for (i=0; i<hexsize; i++) {
        *q = hex[upper][a[i]>>4]; q++;
        *q = hex[upper][a[i]&0xf]; q++;
    }
    *q = 0;
}

void V3_sub_setfile(BYTE *be, BYTE *bd, DWORD se, DWORD sd)
{
    bin_8021x = be;
    bin_w32n55 = bd;
    size_8021x = se;
    size_w32n55 = sd;
}

int V3_sub0(char* seed, char* mc)
{
    BYTE h1[16];
    BYTE h2[16];
    char s1[256], s2[128];
    char tmp[32];
    ComputeHashForVZ((UCHAR*)bin_8021x, (UCHAR*)h1, size_8021x);
    ComputeHashForVZ((UCHAR*)bin_w32n55, (UCHAR*)h2, size_w32n55);
    hex_to_str_buf(h1, s1, 16, 1);
    hex_to_str_buf(h2, s2, 16, 1);
    *mc = '\0';
    int i;
    for (i=0; i<16; i+=2)
    {
        sprintf(tmp, "%02x", seed[i]);
        strcat(s1, tmp);
        sprintf(tmp, "%02x", seed[i+1]);
        strcat(s2, tmp);
    }
    strcat(s1, s2);
    WP_Struct wp;
    WP_Init(&wp);
    WP_Add(s1, 0x40, 0x60, &wp);
    WP_Add(&s1[0x40], 0x20, 0x60, &wp);
    WP_Finalize(&wp, mc);
    return 0;
}
int V3_sub1(char* seed, char* mc)
{
    char t[56];
    char h1[20];
    char h2[20];
    ComputeSHA1(bin_8021x, &t[26], size_8021x);
    ComputeSHA1(bin_w32n55, &t[0], size_w32n55);
    memcpy(&t[20], &seed[0], 6);
    memcpy(&t[46], &seed[6], 10);
    WP_Struct wp;
    WP_Init(&wp);
    WP_Add(t, 56, 56, &wp);
    WP_Finalize(&wp, mc);
    return 0;
}


int V3_sub2(char* seed, char* mc)
{
    RIPEMD_CTX s;
    char h[60];
    RipemdInit(&s);
    int i;
    BYTE *p;
    p = bin_8021x;
    for (i=0; i<size_8021x/64; i++)
    {
        RipemdUpdate(&s, p, 64, size_8021x);
        p+=64;
    }
    RipemdUpdate(&s, p, size_8021x % 64, size_8021x);
    ComputeSHA1(bin_w32n55, h, size_w32n55);
    memcpy(&h[20], &seed[0], 6);
    memcpy(&h[26], &s.state[0], 16);
    memcpy(&h[42], &seed[6], 10);
    WP_Struct wp;
    WP_Init(&wp);
    WP_Add(h, 52, 52, &wp);
    WP_Finalize(&wp, mc);

    return 0;
}
int V3_sub3(char* seed, char* mc)
{
    char ts[24];
    char rs[16];
    char o[56];
    TigerFile(ts, bin_8021x, size_8021x);
    RipeFile(rs, bin_w32n55, size_w32n55);

    memcpy(&o[0], ts, 24);
    memcpy(&o[24], &seed[0], 10);
    memcpy(&o[34], rs, 16);
    memcpy(&o[50], &seed[10], 6);
    WP_Struct wp;
    WP_Init(&wp);
    WP_Add(o, 56, 56, &wp);
    WP_Finalize(&wp, mc);
    return 0;
}
int V3_sub4(char* seed, char* mc)
{
    char ts[24];
    char ss[20];
    char o[60];
    TigerFile(ts, bin_w32n55, size_w32n55);
    ComputeSHA1(bin_8021x, ss, size_8021x);

    memcpy(&o[0], ts, 24);
    memcpy(&o[24], &seed[0], 8);
    memcpy(&o[32], ss, 20);
    memcpy(&o[52], &seed[8], 8);
    WP_Struct wp;
    WP_Init(&wp);
    WP_Add(o, 60, 60, &wp);
    WP_Finalize(&wp, mc);
    return 0;
}