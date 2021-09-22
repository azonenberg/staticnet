//curve25519 implementation from tweetnacl

#ifndef TWEETNACL_H
#define TWEETNACL_H

#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];
extern void randombytes(u8 *,u64);

int crypto_scalarmult_base(unsigned char *,const unsigned char *);
int crypto_scalarmult(unsigned char *,const unsigned char *,const unsigned char *);

int crypto_verify_16(const unsigned char *,const unsigned char *);
int crypto_verify_32(const unsigned char *,const unsigned char *);

int crypto_sign(uint8_t *sm, uint64_t *smlen, const uint8_t *m, uint64_t n, const uint8_t *sk);

int crypto_hashblocks(u8 *x,const u8 *m,u64 n);
int crypto_hash(u8 *out,const u8 *m,u64 n);
int crypto_sign(u8 *sm,u64 *smlen,const u8 *m,u64 n,const u8 *sk);

#endif
