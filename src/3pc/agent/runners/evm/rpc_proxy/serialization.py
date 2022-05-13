import eth_utils
import struct

UINT256_LEN = 32
UINT64_LEN = 8
ADDRESS_LEN = 20

def pack_uint256be(val: int, trim: bool = False) -> bytes:
    if val == 0:
        if trim:
            return bytes(1) ## 0x0
        else:
            return bytearray(UINT256_LEN)
    dat = eth_utils.int_to_big_endian(val)
    ext = bytearray(UINT256_LEN - len(dat)) + dat
    return ext

def pack_uint256be_hex(val: int) -> str:
    if val == 0:
        return "0x0"
    return "0x" + rlp_pack_uint256be(val).hex()

def unpack_uint256be(buf: bytes) -> int:
    if len(buf) == 0:
        return 0
    val = eth_utils.big_endian_to_int(buf)
    return val

def rlp_pack_uint256be(val: int) -> bytes:
    if val == 0:
        return bytearray()
    return eth_utils.int_to_big_endian(val)

def unpack_hex_uint256be(dat: str) -> int:
    un_prefixed = eth_utils.remove_0x_prefix(dat)
    if len(un_prefixed) % 2 != 0:
        un_prefixed = '0' + un_prefixed
    buf = bytes.fromhex(un_prefixed)
    return unpack_uint256be(buf)

def pack_bytes(dat: bytes) -> bytes:
    sz_dat = struct.pack('Q', len(dat))
    return sz_dat + dat

def pack(obj) -> bytes:
    if isinstance(obj, bool):
        return struct.pack('?', obj)
    elif isinstance(obj, bytes):
        return pack_bytes(obj)
    else:
        raise TypeError('Unable to serialize', type(obj))

def unpack_bytes(buf: bytes) -> tuple:
    offset = 8
    (sz,) = struct.unpack('Q', buf[:offset])
    offset += sz
    dat = buf[8:offset]
    return (dat, offset)

def unpack_dict(buf: bytes) -> dict:
    (sz,) = struct.unpack('Q', buf[:8])
    ret = {}
    offset = 8
    for _ in range(sz):
        (k, o) = unpack_bytes(buf[offset:])
        offset += o
        (v, o) = unpack_bytes(buf[offset:])
        offset += o
        ret[k] = v

    return ret

def unpack(t: type, buf: bytes):
    if t == dict:
        return unpack_dict(buf)
    else:
        raise ValueError('Unable to deserialize', t)
