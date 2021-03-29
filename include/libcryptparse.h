
#ifndef LIBCRYPTPARSE_H
#define LIBCRYPTPARSE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum crypto_type {
	crypto_type_unknown,
	crypto_type_cipher,
        crypto_type_ablkcipher,
        crypto_type_akcipher,
        crypto_type_blkcipher,
        crypto_type_givcipher,
        crypto_type_skcipher,
        crypto_type_aead,
        crypto_type_nivaead,
        crypto_type_ahash,
        crypto_type_shash,
        crypto_type_compression,
        crypto_type_digest,
        crypto_type_kpp,
        crypto_type_pcomp,
        crypto_type_scomp,
        crypto_type_rng
};

enum crypto_alg_fields {
	crypto_alg_type =        0x00001,
	crypto_alg_name =        0x00002,
	crypto_alg_driver =      0x00004,
	crypto_alg_module =      0x00008,
	crypto_alg_priority =    0x00010,
	crypto_alg_refcnt =      0x00020,
	crypto_alg_async =       0x00040,
	crypto_alg_blocksize =   0x00080,
	crypto_alg_chunksize =   0x00100,
	crypto_alg_digestsize =  0x00200,
	crypto_alg_geniv =       0x00400,
	crypto_alg_internal =    0x00800,
	crypto_alg_ivsize =      0x01000,
	crypto_alg_maxauthsize = 0x02000,
	crypto_alg_max_keysize = 0x04000,
	crypto_alg_min_keysize = 0x08000,
	crypto_alg_seedsize =    0x10000,
	crypto_alg_selftest =    0x20000,
	crypto_alg_walksize =    0x40000
};

struct crypto_alg {
	// Used fields mask
	uint32_t used_fields;
	// Required fields
	char *type; // change to crypto_type
	char *name;
	char *driver;
	char *module;
	unsigned priority;
	// Optional fields
	unsigned refcnt;
	bool async;
	unsigned blocksize;
	unsigned chunksize;
	unsigned digestsize;
	char *geniv;
	bool internal;
	unsigned ivsize;
	unsigned maxauthsize;
	unsigned max_keysize;
	unsigned min_keysize;
	unsigned seedsize;
	bool selftest;
	unsigned walksize;
};

int crypto_parse(FILE *fp, struct crypto_alg **algorithms);

#endif // LIBCRYPTPARSE_H
