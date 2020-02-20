/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <openssl/bn.h>

#include "RSA_augment_key.h"

/*
 * If key has d, e and n, but not p, q, dmp1, dmq1 and iqmp, try
 * to calculate these extra factors.  Return 1 on success or 0
 * on failure.  (The key may still be useable even if this fails.)
 */
int RSA_augment_key(RSA *key, int invert)
{
	const BIGNUM *key_n;
	const BIGNUM *key_e;
	const BIGNUM *key_d;
	BN_CTX *ctx = NULL;
	BIGNUM *ktot = NULL;
	BIGNUM *t = NULL;
	BIGNUM *tmp = NULL;
	BIGNUM *a = NULL;
	BIGNUM *two = NULL;
	BIGNUM *l00 = NULL;
	BIGNUM *cand = NULL;
	BIGNUM *k = NULL;
	BIGNUM *n_1 = NULL;
	BIGNUM *key_p = NULL;
	BIGNUM *key_q = NULL;
	BIGNUM *key_dmp1 = NULL;
	BIGNUM *key_dmq1 = NULL;
	BIGNUM *key_iqmp = NULL;
	BIGNUM ***bn_i;
	BIGNUM **bn_free[] = {
		&ktot, &t, &tmp, &a, &two, &l00, &cand, &k, &n_1,
		&key_p, &key_q, &key_dmp1, &key_dmq1, &key_iqmp,
		NULL
	};
	int spotted = 0;
	int ret = 0;

	if (!key) {
		goto cleanup;
	}

	RSA_get0_key(key, &key_n, &key_e, &key_d);

	if (!key_d || !key_e || !key_n) {
		goto cleanup;
	}

	if ((ctx = BN_CTX_new()) == NULL) {
		goto cleanup;
	}
	if ((ktot = BN_new()) == NULL) {
		goto cleanup;
	}
	if ((t = BN_new()) == NULL) {
		goto cleanup;
	}
	if ((tmp = BN_new()) == NULL) {
		goto cleanup;
	}

	if (!BN_dec2bn(&a,   "2")) {
		goto cleanup;
	}
	if (!BN_dec2bn(&two, "2")) {
		goto cleanup;
	}
	if (!BN_dec2bn(&l00, "100")) {
		goto cleanup;
	}

	if ((cand = BN_new()) == NULL) {
		goto cleanup;
	}
	if ((k = BN_new()) == NULL) {
		goto cleanup;
	}
	if ((n_1 = BN_new()) == NULL) {
		goto cleanup;
	}
	if (!BN_sub(n_1, key_n, BN_value_one())) {
		goto cleanup;
	}

	/*
	 * # Compute factors p and q from the private exponent d.
	 * # We assume that n has no more than two factors.
	 * # See 8.2.2(i) in Handbook of Applied Cryptography.
	 * ktot = d*e-1
	 */
	if (!BN_mul(tmp, key_d, key_e, ctx)) {
		goto cleanup;
	}
	if (!BN_sub(ktot, tmp, BN_value_one())) {
		goto cleanup;
	}

	/*
	 * # The quantity d*e-1 is a multiple of phi(n), even,
	 * # and can be represented as t*2^s.
	 * t = ktot
	 */
	if (!BN_copy(t, ktot)) {
		goto cleanup;
	}

	/*
	 * while t%2==0:
	 *     t=divmod(t,2)[0]
	 */
	while (!BN_is_odd(t)) {
		if (!BN_rshift1(t, t)) {
			goto cleanup;
		}
	}

	/*
	 * # Cycle through all multiplicative inverses in Zn.
	 * # The algorithm is non-deterministic, but there is a 50% chance
	 * # any candidate a leads to successful factoring.
	 * # See "Digitalized Signatures and Public Key Functions as Intractable
	 * # as Factorization", M. Rabin, 1979
	 * spotted = 0
	 * a = 2
	 * while not spotted and a<100:
	 */
	while (!spotted && BN_cmp(a, l00) < 0) {

		/*
		 * k = t
		 */
		if (!BN_copy(k, t)) {
			goto cleanup;
		}

		/*
		 * # Cycle through all values a^{t*2^i}=a^k
		 * while k<ktot:
		 */
		while (BN_cmp(k, ktot) < 0) {

			/*
			 * cand = pow(a,k,n)
			 */
			if (!BN_mod_exp(cand, a, k, key_n, ctx)) {
				goto cleanup;
			}

			/*
			 * # Check if a^k is a non-trivial root of unity (mod n)
			 * if cand!=1 and cand!=(n-1) and pow(cand,2,n)==1:
			 */
			if (BN_cmp(cand, BN_value_one()) && BN_cmp(cand, n_1)) {
				if (!BN_mod_exp(tmp, cand, two, key_n, ctx)) {
					goto cleanup;
				}
				if (BN_cmp(tmp, BN_value_one()) == 0) {
					/*
					 * # We have found a number such that (cand-1)(cand+1)=0 (mod n).
					 * # Either of the terms divides n.
					 * obj.p = GCD(cand+1,n)
					 * spotted = 1
					 * break
					 */
					if ((key_p = BN_new()) == NULL) {
						goto cleanup;
					}
					if (!BN_add(tmp, cand, BN_value_one())) {
						goto cleanup;
					}
					if (!BN_gcd(key_p, tmp, key_n, ctx)) {
						goto cleanup;
					}
					spotted = 1;
					break;
				}
			}

			/*
			 * k = k*2
			 */
			if (!BN_lshift1(k, k)) {
				goto cleanup;
			}
		}

		/*
		 * # This value was not any good... let's try another!
		 * a = a+2
		 */
		if (!BN_add(a, a, two)) {
			goto cleanup;
		}
	}

	if (!spotted) {
		/*
		 * Unable to compute factors P and Q from exponent D
		 */
		goto cleanup;
	}

	/*
	 * assert ((n % obj.p)==0)
	 * obj.q = divmod(n,obj.p)[0]
	 */
	key_q = BN_new();
	if (!BN_div(key_q, tmp, key_n, key_p, ctx)) {
		goto cleanup;
	}
	if (!BN_is_zero(tmp)) {
		/*
		 * Curses!
		 * Tricked with a bogus P!
		 */
		goto cleanup;
	}

	if (invert) {
		BIGNUM *x = key_q;
		key_q = key_p;
		key_p = x;
	}

	if ((key_dmp1 = BN_new()) == NULL) {
		goto cleanup;
	}
	if ((key_dmq1 = BN_new()) == NULL) {
		goto cleanup;
	}
	if ((key_iqmp = BN_new()) == NULL) {
		goto cleanup;
	}

	if (!BN_sub(tmp, key_p, BN_value_one())) {
		goto cleanup;
	}
	if (!BN_mod(key_dmp1, key_d, tmp, ctx)) {
		goto cleanup;
	}
	if (!BN_sub(tmp, key_q, BN_value_one())) {
		goto cleanup;
	}
	if (!BN_mod(key_dmq1, key_d, tmp, ctx)) {
		goto cleanup;
	}

	/*
	 * obj.u = inverse(obj.p, obj.q)
	 */
	if (!BN_mod_inverse(key_iqmp, key_q, key_p, ctx)) {
		goto cleanup;
	}

	if (!RSA_set0_factors(key, key_p, key_q)) {
		goto cleanup;
	}
	key_p = key_q = NULL;

	if (!RSA_set0_crt_params(key, key_dmp1, key_dmq1, key_iqmp)) {
		goto cleanup;
	}
	key_dmp1 = key_dmq1 = key_iqmp = NULL;

	if (!RSA_check_key(key)) {
		goto cleanup;
	}

	ret = 1;

cleanup:
	for (bn_i = bn_free;*bn_i != NULL; bn_i++) {
		if (**bn_i != NULL) {
			BN_free(**bn_i);
		}
	}

	BN_CTX_free(ctx);

	return ret;
}
