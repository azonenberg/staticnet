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
int crypto_sign_open(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

int crypto_sign_keypair(u8 *pk, u8 *sk);

int unpackneg(gf r[4],const u8 p[32]);
void reduce(u8 *r);
void scalarmult(gf p[4],gf q[4],const u8 *s);
void scalarbase(gf p[4],const u8 *s);
void add(gf p[4],gf q[4]);
void pack(u8 *r,gf p[4]);
void modL(u8 *r,i64 x[64]);
void pack25519(u8 *o,const gf n);
void unpack25519(gf o, const u8 *n);
void M(gf o,const gf a,const gf b);
void set25519(gf r, const gf a);
void inv25519(gf o,const gf i);
u8 par25519(const gf a);
void Z(gf o,const gf a,const gf b);
void A(gf o,const gf a,const gf b);
void pow2523(gf o,const gf i);
void S(gf o,const gf a);
int neq25519(const gf a, const gf b);

#endif
