import struct
import serialization
import hashlib
import eth_utils
import chainparams
import rlp
import ecdsa
import sha3


class Account:
    def __init__(self, balance: int, nonce: int):
        self.balance = balance
        self.nonce = nonce

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        if len(buf) == 0:
            return (cls(0, 0), 0)
        offset = 0
        balance = serialization.unpack_uint256be(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        nonce = serialization.unpack_uint256be(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        return (cls(balance, nonce), offset)
