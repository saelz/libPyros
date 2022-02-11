#include <assert.h>
#include <stdlib.h>

#include <openssl/evp.h>

#include "hash.h"
#include "libpyros.h"
#include "pyros.h"
#include "str.h"

#define HASHBUFFERSIZE 4096

static char *
hashFileEVP(const char *filename, const EVP_MD *md) {
	FILE *file = fopen(filename, "rb");
	int digest = EVP_MD_size(md);
	unsigned char filehash[digest];
	EVP_MD_CTX *context;
	char *returnhash;
	int bytes_read;
	unsigned char buffer[HASHBUFFERSIZE];

	if (file == NULL)
		return NULL;

	context = EVP_MD_CTX_new();

	EVP_DigestInit(context, md);
	while ((bytes_read = fread(buffer, 1, HASHBUFFERSIZE, file)) != 0)
		EVP_DigestUpdate(context, buffer, bytes_read);
	EVP_DigestFinal(context, filehash, NULL);

	fclose(file);
	EVP_MD_CTX_free(context);

	returnhash = malloc(digest * 2 + 1);
	if (returnhash == NULL)
		return NULL;

	hexToChar(filehash, digest, returnhash);

	return returnhash;
}

char *
getHash(enum PYROS_HASHTYPE hashtype, const char *file) {

	switch (hashtype) {
	case PYROS_MD5HASH:
		return hashFileEVP(file, EVP_md5());
	case PYROS_SHA1HASH:
		return hashFileEVP(file, EVP_sha1());
	case PYROS_SHA256HASH:
		return hashFileEVP(file, EVP_sha256());
	case PYROS_SHA512HASH:
		return hashFileEVP(file, EVP_sha512());
	case PYROS_BLAKE2BHASH:
		return hashFileEVP(file, EVP_blake2b512());
	case PYROS_BLAKE2SHASH:
		return hashFileEVP(file, EVP_blake2s256());
	default:
		return NULL;
	}
}
