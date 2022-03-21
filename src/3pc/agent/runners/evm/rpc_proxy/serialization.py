from multiprocessing.sharedctypes import Value
import struct

UINT256_LEN = 32
UINT64_LEN = 8
ADDRESS_LEN = 20

def pack_uint256be(val: int) -> bytes:
    dat = struct.pack('>Q', val)
    ext = bytearray(UINT256_LEN - len(dat)) + dat
    return ext

def unpack_uint256be(buf: bytes) -> int:
    if len(buf) < UINT64_LEN:
        b = bytearray(UINT64_LEN - len(buf)) + buf
    else:
        b = buf[UINT256_LEN - UINT64_LEN:UINT256_LEN]
    if len(b) == 0:
        return 0
    val = struct.unpack('>Q', b)[0]
    return val

def unpack_hex_uint256be(dat: str) -> int:
    if dat[:2] == '0x':
        dat = dat[2:]
    buf = bytes.fromhex(dat)
    ext_buf = bytearray(UINT64_LEN - len(buf)) + buf
    val = struct.unpack('>Q', ext_buf)[0]
    return val

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
