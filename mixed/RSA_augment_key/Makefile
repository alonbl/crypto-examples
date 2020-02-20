CC = gcc
CCFLAGS = -Wall -Wextra $(shell pkg-config libcrypto --cflags)
LIBS = $(shell pkg-config libcrypto --libs)
LDFLAGS =

all:	\
	RSA_augment_key-test
	$(NULL)

clean:
	rm -f RSA_augment_key-test
	rm -f tmp.*

check:	all
	./RSA_augment_key-test.sh

RSA_augment_key-test:	\
		RSA_augment_key-test.c \
		RSA_augment_key.c \
		$(NULL)
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)
