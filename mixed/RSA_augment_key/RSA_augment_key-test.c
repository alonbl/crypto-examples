#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "RSA_augment_key.h"

static void fatal(const char * const s) {
	fprintf(stderr, "FATAL: %s\n", s);
}

static int fatal_openssl_cb(const char *str, __attribute__((unused)) size_t len, void *u) {
	fprintf(stderr, "FATAL: %s: %s\n", str, (char *)u);
	return 0;
}

static void fatal_openssl(const char * const s) {
	ERR_print_errors_cb(fatal_openssl_cb, (void *)s);
}

int main(int argc, char *argv[]) {
	EVP_PKEY *evpin = NULL;
	EVP_PKEY *evpout = NULL;
	BIO *bioin = NULL;
	BIO *bioout = NULL;
	RSA *rsain = NULL;
	RSA *rsaout = NULL;
	const BIGNUM *n = NULL;
	const BIGNUM *e = NULL;
	const BIGNUM *d = NULL;
	BIGNUM *d_n = NULL;
	BIGNUM *d_e = NULL;
	BIGNUM *d_d = NULL;
	char *infile;
	char *outfile;
	int invert;

	if (argc != 4) {
		fatal("Usage");
		goto cleanup;
	}
	infile = argv[1];
	outfile = argv[2];
	invert = atoi(argv[3]);

	if ((bioin = BIO_new_file(infile, "r")) == NULL) {
		fatal_openssl("BIO_new_file");
		goto cleanup;
	}
	if ((bioout = BIO_new_file(outfile, "w")) == NULL) {
		fatal_openssl("BIO_new_file");
		goto cleanup;
	}

	if ((evpin = PEM_read_bio_PrivateKey(bioin, NULL, NULL, NULL)) == NULL) {
		fatal_openssl("PEM_read_bio_PrivateKey");
		goto cleanup;
	}

	if ((rsain = EVP_PKEY_get1_RSA(evpin)) == NULL) {
		fatal_openssl("EVP_PKEY_get1_RSA");
		goto cleanup;
	}

	RSA_get0_key(rsain, &n, &e, &d);

	if ((rsaout = RSA_new()) == NULL) {
		fatal_openssl("RSA_new");
		goto cleanup;
	}

	d_n = BN_dup(n);
	d_e = BN_dup(e);
	d_d = BN_dup(d);
	if (!RSA_set0_key(rsaout, d_n, d_e, d_d)) {
		fatal_openssl("RSA_set0_key");
	}
	d_n = d_e = d_d = NULL; /* handover to rsaout */

	if (!RSA_augment_key(rsaout, invert)) {
		fatal_openssl("RSA_augment_key");
		goto cleanup;
	}

	if ((evpout = EVP_PKEY_new()) == NULL) {
		fatal_openssl("EVP_PKEY_new");
		goto cleanup;
	}

	if (!EVP_PKEY_assign_RSA(evpout, rsaout)) {
		fatal_openssl("EVP_PKEY_set1_RSA");
		goto cleanup;
	}
	rsaout = NULL; /* handover to evpout */

	if (!PEM_write_bio_PKCS8PrivateKey(bioout, evpout, NULL, NULL, 0, 0, NULL)) {
		fatal_openssl("PEM_write_bio_PKCS8PrivateKey");
		goto cleanup;
	}

cleanup:

	if (d_n != NULL) {
		BN_free(d_n);
	}
	if (d_e != NULL) {
		BN_free(d_e);
	}
	if (d_d != NULL) {
		BN_free(d_d);
	}
	if (rsain != NULL) {
		RSA_free(rsain);
	}
	if (rsaout != NULL) {
		RSA_free(rsaout);
	}
	if (evpin != NULL) {
		EVP_PKEY_free(evpin);
	}
	if (evpout != NULL) {
		EVP_PKEY_free(evpout);
	}
	if (bioin != NULL) {
		BIO_free(bioin);
	}
	if (bioout != NULL) {
		BIO_free(bioout);
	}

	return 0;
}
