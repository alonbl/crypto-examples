#ifndef __RSA_AUGMENT_KEY_H
#define __RSA_AUGMENT_KEY_H
#include <openssl/rsa.h>
int RSA_augment_key(RSA *key, int invert);
#endif
