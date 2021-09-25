//curve25519 implementation from tweetnacl

#ifndef TWEETNACL_H
#define TWEETNACL_H

#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;
typedef i64 gf[16];
extern void randombytes(u8 *,u64);

int crypto_scalarmult_base(unsigned char *,const unsigned char *);
int crypto_scalarmult(unsigned char *,const unsigned char *,const unsigned char *);

int crypto_verify_16(const unsigned char *,const unsigned char *);
int crypto_verify_32(const unsigned char *,const unsigned char *);

int crypto_hashblocks(u8 *x,const u8 *m,u64 n);
int crypto_hash(u8 *out,const u8 *m,u64 n);
int crypto_sign(u8 *sm,u64 *smlen,const u8 *m,u64 n,const u8 *sk);

#endif
