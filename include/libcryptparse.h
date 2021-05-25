
#ifndef LIBCRYPTPARSE_H
#define LIBCRYPTPARSE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum cryptparse_type {
	cryptparse_type_unknown,
	cryptparse_type_cipher,
	cryptparse_type_ablkcipher,
	cryptparse_type_akcipher,
	cryptparse_type_blkcipher,
	cryptparse_type_givcipher,
	cryptparse_type_skcipher,
	cryptparse_type_aead,
	cryptparse_type_nivaead,
	cryptparse_type_ahash,
	cryptparse_type_shash,
	cryptparse_type_compression,
	cryptparse_type_digest,
	cryptparse_type_kpp,
	cryptparse_type_pcomp,
	cryptparse_type_scomp,
	cryptparse_type_rng
};

enum cryptparse_alg_fields {
	cryptparse_alg_type =        0x00001,
	cryptparse_alg_name =        0x00002,
	cryptparse_alg_driver =      0x00004,
	cryptparse_alg_module =      0x00008,
	cryptparse_alg_priority =    0x00010,
	cryptparse_alg_refcnt =      0x00020,
	cryptparse_alg_async =       0x00040,
	cryptparse_alg_blocksize =   0x00080,
	cryptparse_alg_chunksize =   0x00100,
	cryptparse_alg_digestsize =  0x00200,
	cryptparse_alg_geniv =       0x00400,
	cryptparse_alg_internal =    0x00800,
	cryptparse_alg_ivsize =      0x01000,
	cryptparse_alg_maxauthsize = 0x02000,
	cryptparse_alg_max_keysize = 0x04000,
	cryptparse_alg_min_keysize = 0x08000,
	cryptparse_alg_seedsize =    0x10000,
	cryptparse_alg_selftest =    0x20000,
	cryptparse_alg_walksize =    0x40000
};

struct cryptparse_alg {
	// Used fields mask
	uint32_t used_fields;
	// Required fields
	char *type; // change to cryptparse_type
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
	struct cryptparse_alg *next;
};

int cryptparse_parse(char *path, struct cryptparse_alg **algorithms);

void cryptparse_destroy(struct cryptparse_alg *algorithms);

#endif // LIBCRYPTPARSE_H
