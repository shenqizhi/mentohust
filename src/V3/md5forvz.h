/* MD5.H - header file for MD5.C */

/*
Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.*/

#ifndef MD5FORVZ_H
#define MD5FORVZ_H
#include "types.h"

/* MD5 context. */
typedef struct
{
  UINT4 state[4];								   /* state (ABCD) */
  UINT4 count[2];		/* number of bits, modulo 2^64 (lsb first) */
  UCHAR buffer[64];						 /* input buffer */
} MD5_CTXForVZ;

void MD5InitForVZ(MD5_CTXForVZ * context);
void MD5UpdateForVZ(MD5_CTXForVZ *context, UCHAR *input, UINT4 inputLen);
void MD5FinalForVZ(UCHAR digest[16], MD5_CTXForVZ *context);

void ComputeHashForVZ(UCHAR *src, UCHAR *dest, UINT4 len);

#endif /* MD5FORVZ_H */
