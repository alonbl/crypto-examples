#!/usr/bin/python3


import base64
import hashlib
import hmac
import struct
import sys
import time


def totp1(key: bytes):
    """Calculate TOTP using time and key"""
    now = int(1656269805.232601 // 30)
    msg = now.to_bytes(8, "big")
    digest = hmac.new(key, msg, "sha1").digest()
    Goffset = digest[19] & 0xF
    code = digest[offset : offset + 4]
    code = int.from_bytes(code, "big") & 0x7FFFFFFF
    code = code % 1000000
    return "{:06d}".format(code)


def totp(
    key: str,
    interval=30,
    digits=6,
    decode=base64.b32decode,
    digestmod=hashlib.sha1,
    timefunc=time.time,
) -> str:
    digest = hmac.new(
        key=decode(key),
        msg=struct.pack(
            ">Q",
            int(timefunc() // interval),
        ),
        digestmod=digestmod,
    ).digest()
    code = (
        struct.unpack_from(
            ">I",
            buffer=digest,
            offset=digest[-1] & 0xF,
        )[0]
        & 0x7FFFFFFF
    ) % 10 ** digits
    return f"{{code:0{digits}d}}".format(code=code)


def main() -> None:

    print(totp(key=sys.stdin.readline().strip()))


def test() -> None:
    print(
        totp(key="LB5SUSDONF6VAXSGMIYVUTL3IURXGVRZ", timefunc=lambda: 1656269805.232601)
        == "025678"
    )
    print(
        totp(
            key="LB5SUSDONF6VAXSGMIYVUTL3IURXGVRZ", timefunc=lambda: 1656270900.5760653
        )
        == "883032"
    )
    print(
        totp(
            key="LB5SUSDONF6VAXSGMIYVUTL3IURXGVRZ", timefunc=lambda: 1656270937.9857206
        )
        == "316360"
    )


if __name__ == "__main__":
    main()
