#include <stdlib.h>

#include <openssl/evp.h>

#include "pyros.h"
#include "str.h"

#define HASHBUFFERSIZE 1024

char *
hashFileEVP(char *filename, const EVP_MD *md) {
	FILE *file = fopen(filename, "rb");
	int digest = EVP_MD_size(md);
	unsigned char filehash[digest];
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	char *returnhash;
	int bytes;
	unsigned char buffer[HASHBUFFERSIZE];

	if (file == NULL)
		return NULL;

	EVP_DigestInit(context, md);
	while ((bytes = fread(buffer, 1, HASHBUFFERSIZE, file)) != 0)
		EVP_DigestUpdate(context, buffer, bytes);
	EVP_DigestFinal(context, filehash, NULL);

	fclose(file);

	returnhash = malloc(digest * 2 + 1);
	hexToChar(filehash, digest, returnhash);

	EVP_MD_CTX_free(context);
	return returnhash;
}

char *
getMD5(char *file) {
	return hashFileEVP(file, EVP_md5());
}

char *
getSHA1(char *file) {
	return hashFileEVP(file, EVP_sha1());
}
char *
getSHA256(char *file) {
	return hashFileEVP(file, EVP_sha256());
}
char *
getSHA512(char *file) {
	return hashFileEVP(file, EVP_sha512());
}
char *
getBLAKE2B(char *file) {
	return hashFileEVP(file, EVP_blake2b512());
}
char *
getBLAKE2S(char *file) {
	return hashFileEVP(file, EVP_blake2s256());
}
