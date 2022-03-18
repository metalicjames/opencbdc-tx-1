import struct
import serialization
import hashlib

class Transaction:
    def __init__(self, from_addr: bytes, to_addr: bytes, value: int, nonce: int, gas_price: int, gas_limit: int, input_data: bytes):
        # TODO: parameter checks
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.value = value
        self.nonce = nonce
        self.gas_price = gas_price
        self.gas_limit = gas_limit
        self.input_data = input_data

    def pack(self) -> bytes:
        ret = bytes()
        ret += self.from_addr

        has_to = self.to_addr is not None and len(self.to_addr) > 0
        ret += struct.pack('?', has_to)
        if has_to:
            ret += self.to_addr

        ret += serialization.pack_uint256be(self.value)
        ret += serialization.pack_uint256be(self.nonce)
        ret += serialization.pack_uint256be(self.gas_price)
        ret += serialization.pack_uint256be(self.gas_limit)

        if self.input_data is not None:
            ret += struct.pack('Q', len(self.input_data))
            ret += self.input_data
        else:
            ret += struct.pack('Q', 0)

        return ret

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        from_addr = buf[:20]
        assert len(from_addr) == serialization.ADDRESS_LEN
        has_to = struct.unpack('?', buf[20:21])[0]
        to_addr = None
        offset = 21
        if has_to:
            to_addr = buf[21:41]
            offset = 41
            assert len(to_addr) == serialization.ADDRESS_LEN
        value = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        nonce = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        gas_price = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        gas_limit = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        input_data_len = struct.unpack('Q', buf[offset:offset+serialization.UINT64_LEN])[0]
        offset += serialization.UINT64_LEN
        buf_end = offset + input_data_len
        input_data = buf[offset:buf_end]
        return (cls(from_addr, to_addr, value, nonce, gas_price, gas_limit, input_data), buf_end)

    @classmethod
    def from_json(cls, tx: dict):
        from_addr = bytes.fromhex(tx['from'])
        to_addr = None
        if 'to' in tx:
            to_addr = bytes.fromhex(tx['to'])

        value = serialization.unpack_hex_uint256be(tx['value'])
        nonce = serialization.unpack_hex_uint256be(tx['nonce'])
        gas_price = serialization.unpack_hex_uint256be(tx['gasPrice'])
        gas_limit = serialization.unpack_hex_uint256be(tx['gas'])

        input_data = None
        if 'input' in tx:
            input_data = bytes.fromhex(tx['input'])

        return cls(from_addr, to_addr, value, nonce, gas_price, gas_limit, input_data)

    def txid(self) -> bytes:
        buf = self.pack()
        return hashlib.sha256(buf).digest()

    def to_dict(self):
        ret = {
            'from': self.from_addr.hex(),
            'to': self.to_addr.hex() if self.to_addr is not None else None,
            'value': serialization.pack_uint256be(self.value).hex(),
            'nonce': serialization.pack_uint256be(self.nonce).hex(),
            'gas_price': serialization.pack_uint256be(self.gas_price).hex(),
            'gas_limit': serialization.pack_uint256be(self.gas_limit).hex(),
            'input_data': self.input_data.hex() if self.input_data is not None else None
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
        ret = {
            'address': self.addr.hex(),
            'data': self.data.hex(),
            'topics': [t.hex() for t in self.topics]
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
            'transactionHash': self.tx.txid().hex(),
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
