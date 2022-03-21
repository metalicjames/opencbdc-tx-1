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
    tx = transaction.Transaction.from_json(param)
    res = send_transaction(tx, True)
    return '0x' + res.output_data.hex()

def send_tx(param):
    tx = transaction.Transaction.from_json(param)
    return send_transaction(tx, False)

def chain_id():
    return '0xdeadbeef'

def tx_count(address, block):
    # TODO: retrieve this info from shards
    addr_buf = bytes.fromhex(address[2:])
    if addr_buf in addrs:
        return hex(addrs[addr_buf])
    return hex(1)

def get_block(*args):
    null_hash = bytearray(32).hex()
    t = '0x' + struct.pack('>Q', int(time.time())).hex()
    null_addr = bytearray(20).hex()

    blk = {
        'hash': null_hash,
        'parentHash': null_hash,
        'number': '0x01',
        'timestamp': t,
        'gasLimit': '0xffffffff',
        'gasUsed': '0x0',
        'miner': null_addr,
        'extraData': '',
        'baseFeePerGas': '0x0'
    }
    return blk

def estimate_gas(tx):
    # TODO: actually estimate gas
    return '0xffffffffff'

def block_number():
    return '0x01'

def send_raw_transaction(tx):
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

        chainid_int = serialization.unpack_hex_uint256be(chain_id())
        v -= 35 + (chainid_int * 2)

        tx_dat[6] = chainid_int
        tx_dat[7] = bytes()
        tx_dat[8] = bytes()

        rlp_payload = rlp.encode(tx_dat)

    s = ecdsa.ecdsa.Signature(r, y)
    sighash = sha3.keccak_256(rlp_payload).digest()

    g = ecdsa.curves.SECP256k1.generator

    (pk0, pk1) = s.recover_public_keys(eth_utils.big_endian_to_int(sighash), g)
    use_pk = pk0 if v == 0 else pk1

    pk_buf = use_pk.point.to_bytes(encoding='uncompressed')
    addr = sha3.keccak_256(pk_buf[1:]).digest()[-20:]

    t = transaction.Transaction(addr, to_addr, value, nonce, gas_price, gas_limit, input_data)
    txid = sha3.keccak_256(bytes.fromhex(tx[2:])).hexdigest()
    ret = send_transaction(t, False)
    retval = '0x' + txid
    receipts[retval] = ret
    return retval

def get_tx_receipt(txid):
    ret = receipts[txid].to_dict()
    return ret

def client_version():
    return 'opencbdc/v0.0'

def gas_price():
    return '0x0'

def get_tx(txid):
    r = receipts[txid]
    tx = r.tx.to_dict()
    tx['hash'] = txid
    return tx

def main():
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
    server.serve_forever()

if __name__ == '__main__':
    main()

