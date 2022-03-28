import socket
import struct
import jsonrpclib.SimpleJSONRPCServer as rpc
import random

import transaction
import wire
import time
import serialization

import rlp
import ecdsa
import sha3
import eth_utils

HOST = ''
PORT = 6667
LISTEN_HOST = ''
LISTEN_PORT = 8080

addrs = {}
receipts = {}
blocks = []
blk_hashes = {}
contract_code = {}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

def recv_data(id):
    sz_dat = sock.recv(8)
    sz = struct.unpack('Q', sz_dat)[0]

    resp_dat = sock.recv(sz)
    assert resp_dat[:8] == id

    (success,) = struct.unpack('?', resp_dat[8:9])
    if not success:
        return None

    return resp_dat[9:]

def send_req(payload):
    req_id = random.randbytes(8)
    req_sz = len(req_id) + len(payload)
    req = struct.pack('Q', req_sz)
    req += req_id
    req += payload

    sock.sendall(req)

    return recv_data(req_id)

def send_transaction(tx, dry_run):
    exec_req = wire.Request(tx.from_addr, tx.pack(), dry_run)
    resp = send_req(exec_req.pack())

    r = wire.Response.unpack(resp)
    if r.success is not None:
        receipt_buf = r.success[tx.txid()]
        if receipt_buf is None:
            raise ValueError('Invalid response')
        (receipt, _) = transaction.Receipt.unpack(receipt_buf)
        if not dry_run:
            addrs[tx.from_addr] = addrs.get(tx.from_addr, 1) + 1
        return receipt

    raise RuntimeError(r.failure)

def call(param, state):
    print('call', param.items())
    tx = transaction.Transaction.from_json(param)
    res = send_transaction(tx, True)
    return '0x' + res.output_data.hex()

def send_tx(param):
    print('send_tx')
    tx = transaction.Transaction.from_json(param)
    return send_transaction(tx, False)

def chain_id():
    print('chain_id')
    return '0xcbdc'

def tx_count(address, block):
    print('tx_count', address, block)
    # TODO: retrieve this info from shards
    addr_buf = bytes.fromhex(address[2:])
    if addr_buf in addrs:
        return hex(addrs[addr_buf])
    return hex(1)

def make_block(txid):
    null_hash = bytearray(32).hex()
    parent = blocks[-1]['parentHash'] if len(blocks) > 0 else null_hash
    t = '0x' + struct.pack('>Q', int(time.time())).hex()
    null_addr = bytearray(20).hex()
    blk = {
        'hash': txid if txid is not None else null_hash,
        'parentHash': parent,
        'number': hex(len(blocks)),
        'timestamp': t,
        'gasLimit': '0xffffffff',
        'gasUsed': '0x0',
        'miner': null_addr,
        'extraData': '',
        'baseFeePerGas': '0x0',
        'transactions': [txid] if txid is not None else [],
        'nonce': '0x00000000',
        'logsBloom': '0x' + bytearray(256).hex(),
    }
    blk_hashes[txid] = len(blocks)
    blk_hashes['latest'] = len(blocks)
    blocks.append(blk)

def get_block(blk_id, full):
    print('get_block', blk_id, full)
    assert full is False
    if blk_id in blk_hashes:
        return blocks[blk_hashes[blk_id]]

    hex_str = blk_id[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str

    num = eth_utils.big_endian_to_int(bytes.fromhex(hex_str))
    return blocks[num]


def estimate_gas(tx):
    print('estimate_gas')
    # TODO: actually estimate gas
    return '0xffffffffff'

def block_number():
    print('block_number')
    return hex(len(blocks) - 1)

def send_raw_transaction(tx):
    print('send_raw_transaction')
    if tx[2:4] == '02':
        tx_buf = bytes.fromhex(tx[4:])
        txs = rlp.decode(tx_buf)
        value = serialization.unpack_uint256be(txs[6])
        nonce = serialization.unpack_uint256be(txs[1])
        gas_price = serialization.unpack_uint256be(txs[3])
        gas_limit = serialization.unpack_uint256be(txs[4])
        to_addr = tx_dat[5]
        input_data = tx_dat[7]

        r = eth_utils.big_endian_to_int(txs[10])
        y = eth_utils.big_endian_to_int(txs[11])
        v = eth_utils.big_endian_to_int(txs[9])

        rlp_payload = b'\x02' + rlp.encode(txs[:-3])
    else:
        tx_buf = bytes.fromhex(tx[2:])
        tx_dat = rlp.decode(tx_buf)
        value = serialization.unpack_uint256be(tx_dat[4])
        nonce = serialization.unpack_uint256be(tx_dat[0])
        gas_price = serialization.unpack_uint256be(tx_dat[1])
        gas_limit = serialization.unpack_uint256be(tx_dat[2])
        to_addr = tx_dat[3]
        input_data = tx_dat[5]

        r = eth_utils.big_endian_to_int(tx_dat[7])
        y = eth_utils.big_endian_to_int(tx_dat[8])
        v = eth_utils.big_endian_to_int(tx_dat[6])

        if v != 27 and v != 28:
            chainid_int = serialization.unpack_hex_uint256be(chain_id())
            v -= 35 + (chainid_int * 2)

            tx_dat[6] = chainid_int
            tx_dat[7] = bytes()
            tx_dat[8] = bytes()

            rlp_payload = rlp.encode(tx_dat)
        else:
            v -= 27
            rlp_payload = rlp.encode(tx_dat[:-3])

    s = ecdsa.ecdsa.Signature(r, y)
    sighash = sha3.keccak_256(rlp_payload).digest()

    g = ecdsa.curves.SECP256k1.generator

    (pk0, pk1) = s.recover_public_keys(eth_utils.big_endian_to_int(sighash), g)
    use_pk = pk0 if v == 0 else pk1

    pk_buf = use_pk.point.to_bytes(encoding='uncompressed')
    addr = sha3.keccak_256(pk_buf[1:]).digest()[-20:]

    print(v, r, y)

    t = transaction.Transaction(addr, to_addr, value, nonce, gas_price, gas_limit, input_data, v, r, y)
    print(t.to_dict().items())
    txid = sha3.keccak_256(bytes.fromhex(tx[2:])).hexdigest()
    print(t.pack().hex())
    ret = send_transaction(t, False)
    retval = '0x' + txid
    print(retval)
    make_block(retval)
    receipts[retval] = ret
    if ret.create_address is not None:
        contract_code['0x' + ret.create_address.hex()] = ret.output_data
    return retval

def get_tx_receipt(txid):
    print('get_tx_receipt', txid)
    ret = receipts[txid].to_dict()
    ret['transactionHash'] = txid
    print(ret)
    return ret

def client_version():
    print('client_version')
    return 'opencbdc/v0.0'

def gas_price():
    print('gas_price')
    return '0x0'

def get_tx(txid):
    print('get_tx', txid)
    r = receipts[txid]
    tx = r.tx.to_dict()
    tx['hash'] = txid
    return tx

def get_code(addr, state):
    print('get_code', addr, state)
    ret = '0x' + contract_code[addr].hex()
    print(ret)
    return ret

def get_balance(addr, state):
    print('get_balance', addr, state)
    # TODO: implement
    return '0xffffffff'

def accounts():
    return []

def get_logs(params):
    print('get_logs', params)
    ret = set()

    addr_bytes = None
    if 'address' in params:
        addr_bytes = bytes.fromhex(params['address'][2:])

    topics = []
    if 'topics' in params:
        for t in params['topics']:
            if t is None:
                continue
            t_bytes = bytes.fromhex(t[2:])
            topics.append(t_bytes)

    for r in receipts.values():
        for l in r.logs:
            if addr_bytes is not None and l.addr == addr_bytes:
                ret.add(l)
                continue
            for t in topics:
                if t in l.topics:
                    ret.add(l)
                    break

    return [r.to_dict() for r in ret]


def main():
    make_block(None)
    server = rpc.SimpleJSONRPCServer((LISTEN_HOST, LISTEN_PORT))
    server.register_function(send_tx, 'eth_sendTransaction')
    server.register_function(call, 'eth_call')
    server.register_function(chain_id, 'eth_chainId')
    server.register_function(get_block, 'eth_getBlockByNumber')
    server.register_function(tx_count, 'eth_getTransactionCount')
    server.register_function(estimate_gas, 'eth_estimateGas')
    server.register_function(block_number, 'eth_blockNumber')
    server.register_function(send_raw_transaction, 'eth_sendRawTransaction')
    server.register_function(get_tx_receipt, 'eth_getTransactionReceipt')
    server.register_function(client_version, 'web3_clientVersion')
    server.register_function(gas_price, 'eth_gasPrice')
    server.register_function(get_tx, 'eth_getTransactionByHash')
    server.register_function(chain_id, 'net_version')
    server.register_function(get_code, 'eth_getCode')
    server.register_function(get_balance, 'eth_getBalance')
    server.register_function(accounts, 'eth_accounts')
    server.register_function(get_logs, 'eth_getLogs')
    server.serve_forever()

if __name__ == '__main__':
    main()

