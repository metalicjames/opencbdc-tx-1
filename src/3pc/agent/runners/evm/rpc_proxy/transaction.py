import struct
import serialization
import hashlib
import eth_utils

class Transaction:
    def __init__(self, from_addr: bytes, to_addr: bytes, value: int, nonce: int, gas_price: int, gas_limit: int, input_data: bytes, v: int, r: int, s: int):
        # TODO: parameter checks
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.value = value
        self.nonce = nonce
        self.gas_price = gas_price
        self.gas_limit = gas_limit
        self.input_data = input_data
        self.v = v
        self.r = r
        self.s = s

    def pack(self) -> bytes:
        ret = bytes()

        # TX type
        ret += struct.pack('B', 0)

        ret += self.from_addr

        has_to = self.to_addr is not None and len(self.to_addr) > 0
        ret += struct.pack('?', has_to)
        if has_to:
            ret += self.to_addr

        ret += serialization.pack_uint256be(self.value)
        ret += serialization.pack_uint256be(self.nonce)
        ret += serialization.pack_uint256be(self.gas_price)
        ret += serialization.pack_uint256be(self.gas_limit)

        # Tip and fee cap fields
        ret += serialization.pack_uint256be(0)
        ret += serialization.pack_uint256be(0)

        if self.input_data is not None:
            ret += struct.pack('Q', len(self.input_data))
            ret += self.input_data
        else:
            ret += struct.pack('Q', 0)

        # Access lists not yet implemented
        ret += struct.pack('Q', 0)

        v = eth_utils.int_to_big_endian(self.v)
        print(v, len(v))
        ret += bytearray(serialization.UINT256_LEN - len(v)) + v

        r = eth_utils.int_to_big_endian(self.r)
        ret += bytearray(serialization.UINT256_LEN - len(r)) + r

        s = eth_utils.int_to_big_endian(self.s)
        ret += bytearray(serialization.UINT256_LEN - len(s)) + s

        return ret

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        from_addr = buf[1:21]
        assert len(from_addr) == serialization.ADDRESS_LEN
        has_to = struct.unpack('?', buf[21:22])[0]
        to_addr = None
        offset = 22
        if has_to:
            to_addr = buf[22:42]
            offset = 42
            assert len(to_addr) == serialization.ADDRESS_LEN
        value = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        nonce = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        gas_price = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        gas_limit = serialization.unpack_uint256be(buf[offset:])
        offset += 3 * serialization.UINT256_LEN
        input_data_len = struct.unpack('Q', buf[offset:offset+serialization.UINT64_LEN])[0]
        offset += serialization.UINT64_LEN
        buf_end = offset + input_data_len
        input_data = buf[offset:buf_end]
        offset += input_data_len
        (access_list_len,) = struct.unpack('Q', buf[offset:offset+serialization.UINT64_LEN])
        assert access_list_len == 0
        offset += serialization.UINT64_LEN
        v = eth_utils.big_endian_to_int(buf[offset:offset+serialization.UINT256_LEN])
        offset += serialization.UINT256_LEN
        r = eth_utils.big_endian_to_int(buf[offset:offset+serialization.UINT256_LEN])
        offset += serialization.UINT256_LEN
        s = eth_utils.big_endian_to_int(buf[offset:offset+serialization.UINT256_LEN])
        offset += serialization.UINT256_LEN
        return (cls(from_addr, to_addr, value, nonce, gas_price, gas_limit, input_data, v, r, s), offset)

    @classmethod
    def from_json(cls, tx: dict):
        from_addr = bytes.fromhex(tx['from'][2:])
        to_addr = None
        if 'to' in tx:
            to_addr = bytes.fromhex(tx['to'][2:])

        value = 0
        nonce = 0
        gas_price = 0
        gas_limit = 0

        if 'value' in tx:
            value = serialization.unpack_hex_uint256be(tx['value'])
        if 'nonce' in tx:
            nonce = serialization.unpack_hex_uint256be(tx['nonce'])
        if 'gasPrice' in tx:
            gas_price = serialization.unpack_hex_uint256be(tx['gasPrice'])
        if 'gas' in tx:
            gas_limit = serialization.unpack_hex_uint256be(tx['gas'])

        input_data = None
        if 'data' in tx:
            input_data = bytes.fromhex(tx['data'][2:])

        v = eth_utils.big_endian_to_int(bytes.fromhex(tx['v'][2:])) if 'v' in tx else 0
        r = eth_utils.big_endian_to_int(bytes.fromhex(tx['r'][2:])) if 'r' in tx else 0
        s = eth_utils.big_endian_to_int(bytes.fromhex(tx['s'][2:])) if 's' in tx else 0

        return cls(from_addr, to_addr, value, nonce, gas_price, gas_limit, input_data, v, r, s)

    def txid(self) -> bytes:
        buf = self.pack()
        return hashlib.sha256(buf).digest()

    def to_dict(self):
        ret = {
            'from': '0x' + self.from_addr.hex(),
            'to': '0x' + self.to_addr.hex() if self.to_addr is not None else None,
            'value': '0x' + serialization.pack_uint256be(self.value).hex(),
            'nonce': '0x' + serialization.pack_uint256be(self.nonce).hex(),
            'gasPrice': '0x' + serialization.pack_uint256be(self.gas_price).hex(),
            'gas': '0x' + serialization.pack_uint256be(self.gas_limit).hex(),
            'data': self.input_data.hex() if self.input_data is not None else None,
        }
        return ret

class Log:
    def __init__(self, addr: bytes, data: bytes, topics: list):
        # TODO: parameter checks
        self.addr = addr
        self.data = data
        self.topics = topics

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        addr = buf[:serialization.ADDRESS_LEN]
        data_len = struct.unpack('Q', buf[serialization.ADDRESS_LEN:serialization.ADDRESS_LEN+serialization.UINT64_LEN])[0]
        data = buf[serialization.ADDRESS_LEN+serialization.UINT64_LEN:serialization.ADDRESS_LEN+serialization.UINT64_LEN+data_len]
        n_topics = struct.unpack('Q', buf[serialization.ADDRESS_LEN+serialization.UINT64_LEN+data_len:serialization.ADDRESS_LEN+serialization.UINT64_LEN+data_len+serialization.UINT64_LEN])[0]
        topics = []
        buf_start = serialization.ADDRESS_LEN+serialization.UINT64_LEN+data_len+serialization.UINT64_LEN
        for _ in range(n_topics):
            t = buf[buf_start:buf_start+serialization.UINT256_LEN]
            buf_start += serialization.UINT256_LEN
            topics.append(t)
        return (cls(addr, data, topics), buf_start)

    def to_dict(self):
        # TODO: properly fill these fields
        ret = {
            'address': '0x' + self.addr.hex(),
            'data': self.data.hex(),
            'topics': ['0x' + t.hex() for t in self.topics],
            'transactionIndex': '0x0',
            'blockNumber': '0x1',
            'transactionHash': bytearray(32).hex(),
            'blockHash': bytearray(32).hex(),
            'logIndex': '0x0'
        }
        return ret

class Receipt:
    def __init__(self, tx: Transaction, create_address: bytes, gas_used: int, logs: list, output_data: bytes):
        # TODO: parameter checks
        self.tx = tx
        self.create_address = create_address
        self.gas_used = gas_used
        self.logs = logs
        self.output_data = output_data

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        (tx, offset) = Transaction.unpack(buf)
        has_create = struct.unpack('?', buf[offset:offset+1])[0]
        offset += 1
        create_address = None
        if has_create:
            create_address = buf[offset:offset+serialization.ADDRESS_LEN]
            offset += serialization.ADDRESS_LEN
        gas_used = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        n_logs = struct.unpack('Q', buf[offset:offset+serialization.UINT64_LEN])[0]
        offset += serialization.UINT64_LEN
        logs = []
        for _ in range(n_logs):
            (l, o) = Log.unpack(buf[offset:])
            logs.append(l)
            offset += o
        output_data_len = struct.unpack('Q', buf[offset:offset+serialization.UINT64_LEN])[0]
        offset += serialization.UINT64_LEN
        output_data = buf[offset:offset+output_data_len]
        offset += output_data_len
        return (cls(tx, create_address, gas_used, logs, output_data), offset)

    def to_dict(self):
        ret = {
            'transaction': self.tx.to_dict(),
            'from': self.tx.from_addr.hex(),
            'to': self.tx.to_addr.hex() if self.tx.to_addr is not None else None,
            'contractAddress': self.create_address.hex() if self.create_address is not None else None,
            'gasUsed': '0x' + serialization.pack_uint256be(self.gas_used).hex(),
            'cumulativeGasUsed': '0x' + serialization.pack_uint256be(self.gas_used).hex(),
            'logs': [l.to_dict() for l in self.logs],
            'output_data': self.output_data.hex(),
            'success': '0x1',
            'blockNumber': '0x01',
            'blockHash': bytearray(32).hex(),
            'transactionIndex': '0x0'
        }
        return ret
