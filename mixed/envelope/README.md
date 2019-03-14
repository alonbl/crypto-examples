# Encryption Utilities

## Outline

An envelope type encryption to be used in both Java and C++.

## Envelope Format

Format:

```
SIGNATURE|VERSION|CIPHER|KEYID|IV|CIPHERED
```

|Field    |Description                 |
|---------|----------------------------|
|SIGNATURE|Must be `$ENC$`             |
|VERSION  |Must be `0`                 |
|CIPHER   |The ciphered used to encrypt|
|KEYID    |The keyid used to encrypt   |
|IV       |Base64 encoded random IV    |
|CIPHERED |Base64 encoded ciphered data|

Example:

```
$ENC$|0|AES/CBC/PKCS5Padding|1|hBDLzX/rRKeSQfR3dtfdsQ==|VbjTH8Gi2xFnsuQti77pbWgi+DoCcKqmA=
```

The ciphered has first byte with a random index of the plaintext within the ciphered.
This enables to hide the length of the plaintext within the envelope.

## Supported Ciphered

The following are the supported ciphers.

|Name                |Key size|
|--------------------|--------|
|AES/CBC/PKCS5Padding|128     |
|AES/CBC/PKCS5Padding|256     |

Others may be added, although not required for encrypting plain small strings.

## Generating keys

The keys are symmetric base64 encoded.

To generate a key:

```sh
$ dd if=/dev/random bs=1 count=$((KEY_SIZE_IN_BITS / 8)) | base64 -w0
```

Each key should have a unique id to support multiple keys and key rotations.
