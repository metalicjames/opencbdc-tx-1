import struct
import serialization
import hashlib
import eth_utils
import chainparams
import rlp
import ecdsa
import sha3

TX_TYPE_LEGACY = 0
TX_TYPE_ACCESSLIST = 1
TX_TYPE_DYNAMICFEE = 2


class Transaction:
    def __init__(
        self,
        txtype: int,
        to_addr: bytes,
        value: int,
        nonce: int,
        gas_price: int,
        gas_limit: int,
        gas_tip_cap: int,
        gas_fee_cap: int,
        input_data: bytes,
        access_list: list,
        v: int,
        r: int,
        s: int,
        from_addr_cache: bytes = None, # Pass for call type json-deserialized tx
    ):
        self.from_addr_cache = from_addr_cache
        self.txid_cache = None
        self.txtype = txtype
        self.to_addr = to_addr
        self.value = value
        self.nonce = nonce
        self.gas_price = gas_price
        self.gas_limit = gas_limit
        self.gas_tip_cap = gas_tip_cap
        self.gas_fee_cap = gas_fee_cap
        self.input_data = input_data
        self.access_list = access_list
        self.v = v
        self.r = r
        self.s = s

    def pack(self, include_from = False) -> bytes:
        ret = bytes()

        if include_from and self.from_addr_cache is not None:
            ret += self.from_addr_cache

        # TX type
        ret += struct.pack("B", self.txtype)

        has_to = self.to_addr is not None and len(self.to_addr) > 0
        ret += struct.pack("?", has_to)
        if has_to:
            ret += self.to_addr

        ret += serialization.pack_uint256be(self.value)
        ret += serialization.pack_uint256be(self.nonce)
        ret += serialization.pack_uint256be(self.gas_price)
        ret += serialization.pack_uint256be(self.gas_limit)
        ret += serialization.pack_uint256be(self.gas_tip_cap)
        ret += serialization.pack_uint256be(self.gas_fee_cap)

        if self.input_data is not None:
            ret += struct.pack("Q", len(self.input_data))
            ret += self.input_data
        else:
            ret += struct.pack("Q", 0)

        ret += struct.pack("Q", len(self.access_list))
        for access_tuple in self.access_list:
            ret += access_tuple.pack()

        v = eth_utils.int_to_big_endian(self.v)
        ret += bytearray(serialization.UINT256_LEN - len(v)) + v

        r = eth_utils.int_to_big_endian(self.r)
        ret += bytearray(serialization.UINT256_LEN - len(r)) + r

        s = eth_utils.int_to_big_endian(self.s)
        ret += bytearray(serialization.UINT256_LEN - len(s)) + s

        return ret

    @classmethod
    def unpack_rlp(cls, buf: bytes) -> tuple:
        txtype = TX_TYPE_LEGACY
        if int(buf[0]) == TX_TYPE_ACCESSLIST or int(buf[0]) == TX_TYPE_DYNAMICFEE:
            txtype = int(buf[0])
            tx_dat = rlp.decode(buf[1:])
        else:
            tx_dat = rlp.decode(buf)

        offset = 1
        if txtype == TX_TYPE_LEGACY:
            offset = 0

        value = 0
        nonce = 0
        gas_price = 0
        gas_limit = 0
        gas_tip_cap = 0
        gas_fee_cap = 0
        access_list = []

        nonce = serialization.unpack_uint256be(tx_dat[offset])

        offset = offset + 1
        if txtype == TX_TYPE_DYNAMICFEE:
            gas_tip_cap = serialization.unpack_uint256be(tx_dat[offset])
            offset = offset + 1
            gas_fee_cap = serialization.unpack_uint256be(tx_dat[offset])
            offset = offset + 1
        else:
            gas_price = serialization.unpack_uint256be(tx_dat[offset])
            offset = offset + 1
        gas_limit = serialization.unpack_uint256be(tx_dat[offset])
        offset = offset + 1
        to_addr = tx_dat[offset]
        offset = offset + 1
        value = serialization.unpack_uint256be(tx_dat[offset])
        offset = offset + 1
        input_data = tx_dat[offset]
        offset = offset + 1
        if txtype != TX_TYPE_LEGACY:
            access_list = [AccessTuple(v[0], v[1]) for v in tx_dat[offset]]
            offset = offset + 1

        v = serialization.unpack_uint256be(tx_dat[offset])
        offset = offset + 1
        r = serialization.unpack_uint256be(tx_dat[offset])
        offset = offset + 1
        s = serialization.unpack_uint256be(tx_dat[offset])
        return cls(
            txtype,
            to_addr,
            value,
            nonce,
            gas_price,
            gas_limit,
            gas_tip_cap,
            gas_fee_cap,
            input_data,
            access_list,
            v,
            r,
            s,
        )

    def pack_rlp(self, for_sighash: bool = False) -> bytes:
        tx_dat = []
        if self.txtype != TX_TYPE_LEGACY:
            tx_dat.append(serialization.rlp_pack_uint256be(chainparams.chain_id))
        tx_dat.append(serialization.rlp_pack_uint256be(self.nonce))
        if self.txtype == TX_TYPE_DYNAMICFEE:
            tx_dat.append(serialization.rlp_pack_uint256be(self.gas_tip_cap))
            tx_dat.append(serialization.rlp_pack_uint256be(self.gas_fee_cap))
        else:
            tx_dat.append(serialization.rlp_pack_uint256be(self.gas_price))
        tx_dat.append(serialization.rlp_pack_uint256be(self.gas_limit))
        if self.to_addr == None:
            tx_dat.append(bytes())
        else:
            tx_dat.append(self.to_addr)
        tx_dat.append(serialization.rlp_pack_uint256be(self.value))
        tx_dat.append(self.input_data)
        if self.txtype != TX_TYPE_LEGACY:
            tx_dat.append([[at.addr, at.storage_keys] for at in self.access_list])
        if (
            for_sighash
            and self.txtype == TX_TYPE_LEGACY
            and self.v != 27
            and self.v != 28
        ):
            tx_dat.append(serialization.rlp_pack_uint256be(chainparams.chain_id))
            tx_dat.append(serialization.rlp_pack_uint256be(0))
            tx_dat.append(serialization.rlp_pack_uint256be(0))
        elif not for_sighash:
            tx_dat.append(serialization.rlp_pack_uint256be(self.v))
            tx_dat.append(serialization.rlp_pack_uint256be(self.r))
            tx_dat.append(serialization.rlp_pack_uint256be(self.s))

        rlp_buf = rlp.encode(tx_dat)

        if self.txtype == TX_TYPE_LEGACY:
            return rlp_buf
        else:
            return bytes([self.txtype]) + rlp_buf

    def from_addr(self) -> bytes:
        if self.from_addr_cache is None:

            v = self.v
            if self.txtype == TX_TYPE_LEGACY:
                if v != 27 and v != 28:
                    v -= 35 + (chainparams.chain_id * 2)
                else:
                    v -= 27
            sig = ecdsa.ecdsa.Signature(self.r, self.s)
            rlp = self.pack_rlp(True)
            sighash = sha3.keccak_256(rlp).digest()
            g = ecdsa.curves.SECP256k1.generator
            sighash_int = eth_utils.big_endian_to_int(sighash)
            (pk0, pk1) = sig.recover_public_keys(sighash_int, g)
            use_pk = pk0 if v == 0 else pk1
            pk_buf = use_pk.point.to_bytes(encoding="uncompressed")
            self.from_addr_cache = sha3.keccak_256(pk_buf[1:]).digest()[-20:]
        return self.from_addr_cache

    def txid(self) -> bytes:
        if self.txid_cache is None:
            self.txid_cache = sha3.keccak_256(self.pack_rlp()).digest()
        return self.txid_cache

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        txtype = struct.unpack("B", buf[0:1])[0]
        has_to = struct.unpack("?", buf[1:2])[0]
        to_addr = None
        offset = 2
        if has_to:
            to_addr = buf[2:22]
            offset = 22
            assert len(to_addr) == serialization.ADDRESS_LEN
        value = serialization.unpack_uint256be(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        nonce = serialization.unpack_uint256be(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        gas_price = serialization.unpack_uint256be(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        gas_limit = serialization.unpack_uint256be(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        gas_tip_cap = serialization.unpack_uint256be(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        gas_fee_cap = serialization.unpack_uint256be(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        input_data_len = struct.unpack(
            "Q", buf[offset : offset + serialization.UINT64_LEN]
        )[0]
        offset += serialization.UINT64_LEN
        buf_end = offset + input_data_len
        input_data = buf[offset:buf_end]
        offset += input_data_len
        (access_list_len,) = struct.unpack(
            "Q", buf[offset : offset + serialization.UINT64_LEN]
        )
        access_list = []
        for _ in range(access_list_len):
            (at, offset) = AccessTuple.unpack(buf[offset:])
            access_list.append(at)

        offset += serialization.UINT64_LEN
        v = eth_utils.big_endian_to_int(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        r = eth_utils.big_endian_to_int(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        s = eth_utils.big_endian_to_int(
            buf[offset : offset + serialization.UINT256_LEN]
        )
        offset += serialization.UINT256_LEN
        return (
            cls(
                txtype,
                to_addr,
                value,
                nonce,
                gas_price,
                gas_limit,
                gas_tip_cap,
                gas_fee_cap,
                input_data,
                access_list,
                v,
                r,
                s,
            ),
            offset,
        )

    @classmethod
    def from_json(cls, tx: dict):
        txtype = TX_TYPE_LEGACY
        if "type" in tx:
            txtype = tx["type"]

        from_addr = bytes.fromhex(tx["from"][2:])
        to_addr = None
        if "to" in tx:
            to_addr = bytes.fromhex(tx["to"][2:])

        value = 0
        nonce = 0
        gas_price = 0
        gas_limit = 0
        gas_tip_cap = 0
        gas_fee_cap = 0
        access_list = []

        if "value" in tx:
            value = serialization.unpack_hex_uint256be(tx["value"])
        if "nonce" in tx:
            nonce = serialization.unpack_hex_uint256be(tx["nonce"])
        if "gasPrice" in tx:
            gas_price = serialization.unpack_hex_uint256be(tx["gasPrice"])
        if "gas" in tx:
            gas_limit = serialization.unpack_hex_uint256be(tx["gas"])
        if "accessList" in tx:
            access_list = [AccessTuple.from_dict(at) for at in tx["accessList"]]
        if "maxPriorityFeePerGas" in tx:
            gas_tip_cap = serialization.unpack_hex_uint256be(tx["maxPriorityFeePerGas"])
        if "maxFeePerGas" in tx:
            gas_fee_cap = serialization.unpack_hex_uint256be(tx["maxFeePerGas"])

        input_data = None
        if "data" in tx:
            input_data = bytes.fromhex(tx["data"][2:])

        v = eth_utils.big_endian_to_int(bytes.fromhex(tx["v"][2:])) if "v" in tx else 0
        r = eth_utils.big_endian_to_int(bytes.fromhex(tx["r"][2:])) if "r" in tx else 0
        s = eth_utils.big_endian_to_int(bytes.fromhex(tx["s"][2:])) if "s" in tx else 0

        return cls(
            txtype,
            to_addr,
            value,
            nonce,
            gas_price,
            gas_limit,
            gas_tip_cap,
            gas_fee_cap,
            input_data,
            access_list,
            v,
            r,
            s,
            from_addr
        )

    def to_dict(self):
        from_addr = self.from_addr()
        ret = {
            "type": serialization.pack_uint256be_hex(self.txtype),
            "from": "0x" + from_addr.hex(),
            "to": "0x" + self.to_addr.hex() if self.to_addr is not None else None,
            "value": serialization.pack_uint256be_hex(self.value),
            "nonce": serialization.pack_uint256be_hex(self.nonce),
            "gas": serialization.pack_uint256be_hex(self.gas_limit),
            "data": "0x" + self.input_data.hex()
            if self.input_data is not None
            else None,
        }

        if self.txtype == TX_TYPE_DYNAMICFEE:
            ret["maxPriorityFeePerGas"] = serialization.pack_uint256be_hex(
                self.gas_tip_cap
            )
            ret["maxFeePerGas"] = serialization.pack_uint256be_hex(self.gas_fee_cap)

        else:
            ret["gasPrice"] = "0x" + serialization.pack_uint256be_hex(self.gas_limit)

        if self.txtype != TX_TYPE_LEGACY:
            ret["accessList"] = [at.to_dict() for at in self.access_list]

        return ret


class AccessTuple:
    def __init__(self, addr: bytes, storage_keys: list):
        self.addr = addr
        self.storage_keys = storage_keys

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        addr = buf[: serialization.ADDRESS_LEN]
        n_storage_keys = struct.unpack(
            "Q",
            buf[
                serialization.ADDRESS_LEN : serialization.ADDRESS_LEN
                + serialization.UINT64_LEN
            ],
        )[0]
        storage_keys = []
        buf_start = serialization.ADDRESS_LEN + serialization.UINT64_LEN
        for _ in range(n_storage_keys):
            t = buf[buf_start : buf_start + serialization.UINT256_LEN]
            buf_start += serialization.UINT256_LEN
            storage_keys.append(t)
        return (cls(addr, storage_keys), buf_start)

    def pack(self) -> bytes:
        ret = bytes()
        ret += self.addr
        ret += struct.pack("Q", len(self.storage_keys))
        for storage_addr in self.storage_keys:
            ret += storage_addr

        return ret

    def to_dict(self):
        ret = {
            "address": "0x" + self.addr.hex(),
            "storageKeys": ["0x" + sa.hex() for sa in self.storage_keys],
        }
        return ret

    @classmethod
    def from_dict(cls, al: dict):
        addr = bytes.fromhex(al["address"][2:])
        storage_keys = [bytes.fromhex(sk[2:]) for sk in al["storageKeys"]]
        return cls(addr, storage_keys)


class Log:
    def __init__(self, addr: bytes, data: bytes, topics: list):
        # TODO: parameter checks
        self.addr = addr
        self.data = data
        self.topics = topics

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        addr = buf[: serialization.ADDRESS_LEN]
        data_len = struct.unpack(
            "Q",
            buf[
                serialization.ADDRESS_LEN : serialization.ADDRESS_LEN
                + serialization.UINT64_LEN
            ],
        )[0]
        data = buf[
            serialization.ADDRESS_LEN
            + serialization.UINT64_LEN : serialization.ADDRESS_LEN
            + serialization.UINT64_LEN
            + data_len
        ]
        n_topics = struct.unpack(
            "Q",
            buf[
                serialization.ADDRESS_LEN
                + serialization.UINT64_LEN
                + data_len : serialization.ADDRESS_LEN
                + serialization.UINT64_LEN
                + data_len
                + serialization.UINT64_LEN
            ],
        )[0]
        topics = []
        buf_start = (
            serialization.ADDRESS_LEN
            + serialization.UINT64_LEN
            + data_len
            + serialization.UINT64_LEN
        )
        for _ in range(n_topics):
            t = buf[buf_start : buf_start + serialization.UINT256_LEN]
            buf_start += serialization.UINT256_LEN
            topics.append(t)
        return (cls(addr, data, topics), buf_start)

    def to_dict(self):
        # TODO: properly fill these fields
        ret = {
            "address": "0x" + self.addr.hex(),
            "data": self.data.hex(),
            "topics": ["0x" + t.hex() for t in self.topics],
            "transactionIndex": "0x0",
            "blockNumber": "0x1",
            "transactionHash": bytearray(32).hex(),
            "blockHash": bytearray(32).hex(),
            "logIndex": "0x0",
        }
        return ret


class Receipt:
    def __init__(
        self,
        tx: Transaction,
        create_address: bytes,
        gas_used: int,
        logs: list,
        output_data: bytes,
    ):
        # TODO: parameter checks
        self.tx = tx
        self.create_address = create_address
        self.gas_used = gas_used
        self.logs = logs
        self.output_data = output_data

    @classmethod
    def unpack(cls, buf: bytes) -> tuple:
        print("Transaction receipt: [{}]".format(buf.hex()))
        (tx, offset) = Transaction.unpack(buf)
        has_create = struct.unpack("?", buf[offset : offset + 1])[0]
        offset += 1
        create_address = None
        if has_create:
            create_address = buf[offset : offset + serialization.ADDRESS_LEN]
            offset += serialization.ADDRESS_LEN
        gas_used = serialization.unpack_uint256be(buf[offset:])
        offset += serialization.UINT256_LEN
        n_logs = struct.unpack("Q", buf[offset : offset + serialization.UINT64_LEN])[0]
        offset += serialization.UINT64_LEN
        logs = []
        for _ in range(n_logs):
            (l, o) = Log.unpack(buf[offset:])
            logs.append(l)
            offset += o
        output_data_len = struct.unpack(
            "Q", buf[offset : offset + serialization.UINT64_LEN]
        )[0]
        offset += serialization.UINT64_LEN
        output_data = buf[offset : offset + output_data_len]
        offset += output_data_len
        return (cls(tx, create_address, gas_used, logs, output_data), offset)

    def to_dict(self):
        ret = {
            "transaction": self.tx.to_dict(),
            "from": self.tx.from_addr().hex(),
            "to": self.tx.to_addr.hex() if self.tx.to_addr is not None else None,
            "contractAddress": self.create_address.hex()
            if self.create_address is not None
            else None,
            "gasUsed": serialization.pack_uint256be_hex(self.gas_used),
            "cumulativeGasUsed": serialization.pack_uint256be_hex(self.gas_used),
            "logs": [l.to_dict() for l in self.logs],
            "output_data": self.output_data.hex(),
            "success": "0x1",
            "blockNumber": "0x01",
            "blockHash": bytearray(32).hex(),
            "transactionIndex": "0x0",
        }
        return ret
