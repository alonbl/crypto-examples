#!/bin/sh

die() {
	local m="$1"
	echo "FATAL: ${m}" >&2
	exit 1
}

#VALGRIND="valgrind --leak-check=full --leak-resolution=high --track-origins=yes -q --error-exitcode=55"

for keysize in 1024 2048 4096 8192; do
	i=0
	while [ ${i} -lt 10 ]; do
		echo "${keysize}/${i}"
		openssl genpkey -out tmp.in.pkey -algorithm rsa -pkeyopt rsa_keygen_bits:${keysize}
		${VALGRIND} ./RSA_augment_key-test tmp.in.pkey tmp.out.0.pkey 0
		${VALGRIND} ./RSA_augment_key-test tmp.in.pkey tmp.out.1.pkey 1
		cmp tmp.in.pkey tmp.out.0.pkey || cmp tmp.in.pkey tmp.out.1.pkey || die "BAD"

		i="$((${i} + 1))"
	done
done
