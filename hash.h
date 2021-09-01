#ifndef PYROS_HASH_H
#define PYROS_HASH_H
char *getMD5    (const char *file);
char *getSHA1   (const char *file);
char *getSHA256 (const char *file);
char *getSHA512 (const char *file);
char *getBLAKE2B(const char *file);
char *getBLAKE2S(const char *file);
#endif
