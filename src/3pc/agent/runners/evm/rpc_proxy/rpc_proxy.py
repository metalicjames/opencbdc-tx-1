import struct
import random
import asyncio
import ajsonrpc
import sys
import getopt
import h11

import transaction
import wire
import time
import serialization
import rlp
import ecdsa
import sha3
import eth_utils

agent_host = '127.0.0.1'
agent_port = 6666
listen_host = '0.0.0.0'
listen_port = 8080

try:
    opts, args = getopt.getopt(sys.argv[1:], "hi:o:", [
                               "agent_host=", "agent_port=", "listen_host=", "listen_port="])
except getopt.GetoptError:
    print('rpc_proxy.py --agent_host <agent host> --agent_port <agent port> --listen_host <listen host> --listen_port <listen_port>')
    sys.exit(2)
for opt, arg in opts:
    if opt == '-h':
        print('rpc_proxy.py --agent_host <agent host> --agent_port <agent port> --listen_host <listen host> --listen_port <listen_port>')
        sys.exit()
    elif opt in ("-ah", "--agent_host"):
        agent_host = arg
    elif opt in ("-ap", "--agent_port"):
        agent_port = arg
    elif opt in ("-lh", "--listen_host"):
        listen_host = arg
    elif opt in ("-lp", "--listen_port"):
        listen_port = arg
print('connecting to agent on:', str(agent_host) + ":" + str(agent_port))
print('rpc proxy listening on:', str(listen_host) + ":" + str(listen_port))

addrs = {}
receipts = {}
blocks = []
blk_hashes = {}
contract_code = {}

requests = {}

loop = asyncio.get_event_loop()


async def connect():
    return await asyncio.open_connection(agent_host, agent_port)

reader, writer = loop.run_until_complete(connect())


async def do_recv():
    sz_dat = await reader.readexactly(8)
    sz = struct.unpack('Q', sz_dat)[0]

    resp_dat = await reader.readexactly(sz)
    resp_id = resp_dat[:8]
    resp_fut = requests.get(resp_id)
    assert resp_fut is not None

    (success,) = struct.unpack('?', resp_dat[8:9])
    resp_fut.set_result((success, resp_dat[9:]))
    print('got resp', resp_id.hex(), success)
    loop.create_task(do_recv())


async def recv_data(fut, req_id):
    await fut
    del requests[req_id]
    return fut.result()


async def send_req(payload):
    req_id = random.randbytes(8)
    req_sz = len(req_id) + len(payload)
    req = struct.pack('Q', req_sz)
    req += req_id
    req += payload

    fut = loop.create_future()
    requests[req_id] = fut

    writer.write(req)
    await writer.drain()

    print('awaiting recv')
    res = await recv_data(fut, req_id)
    return res


async def send_transaction(tx, dry_run):
    exec_req = wire.Request(tx.from_addr, tx.pack(), dry_run)
    print('awaiting send')
    (success, resp) = await send_req(exec_req.pack())
    if not success:
        raise RuntimeError('RPC request failed')
    print('got resp in send', resp)

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


async def call(param, state):
    print('call', param.items())
    tx = transaction.Transaction.from_json(param)
    res = await send_transaction(tx, True)
    return '0x' + res.output_data.hex()


async def send_tx(param):
    print('send_tx')
    tx = transaction.Transaction.from_json(param)
    return await send_transaction(tx, False)


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


async def send_raw_transaction(tx):
    print('send_raw_transaction')
    if tx[2:4] == '02':
        tx_buf = bytes.fromhex(tx[4:])
        txs = rlp.decode(tx_buf)
        value = serialization.unpack_uint256be(txs[6])
        nonce = serialization.unpack_uint256be(txs[1])
        gas_price = serialization.unpack_uint256be(txs[3])
        gas_limit = serialization.unpack_uint256be(txs[4])
        to_addr = txs[5]
        input_data = txs[7]

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

    t = transaction.Transaction(
        addr,
        to_addr,
        value,
        nonce,
        gas_price,
        gas_limit,
        input_data,
        v,
        r,
        y)
    print(t.to_dict().items())
    txid = sha3.keccak_256(bytes.fromhex(tx[2:])).hexdigest()
    print(t.pack().hex())
    print('awaiting')
    ret = await send_transaction(t, False)
    print('got res')
    retval = '0x' + txid
    print(retval)
    make_block(retval)
    receipts[retval] = ret
    if ret.create_address is not None:
        contract_code['0x' + ret.create_address.hex()] = ret.output_data
    print('returning', ret)
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
    return '0xffffffffffffffffffffffffffffff'


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


class JSONRPCProtocol(asyncio.Protocol):
    def __init__(self, json_rpc_manager):
        self.connection = h11.Connection(h11.SERVER)
        self.json_rpc_manager = json_rpc_manager
        self.request_body = ''

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data: bytes):
        if self.connection.our_state is h11.MUST_CLOSE:
            self.transport.close()
            return

        print('got data', len(data))
        self.connection.receive_data(data)
        self.deliver_events()

    def deliver_events(self):
        more_events = True
        while more_events:
            event = self.connection.next_event()
            more_events = self.handle_event(event)

    def handle_event(self, event) -> bool:
        print('got HTTP event', type(event))
        if isinstance(event, h11.Request):
            if event.method != b'POST':
                raise RuntimeError('Method must be POST')
            if len(self.request_body) != 0:
                raise RuntimeError('Already a pending request')
            return True

        if isinstance(event, h11.Data):
            self.request_body += event.data.decode('utf-8')
            return True

        if isinstance(event, h11.EndOfMessage):
            task = asyncio.create_task(
                self.json_rpc_manager.get_payload_for_payload(
                    self.request_body))
            task.add_done_callback(self.handle_task_result)
            self.request_body = ''
            return True

        if isinstance(event, h11.ConnectionClosed):
            return False

        if event is h11.NEED_DATA:
            if self.connection.client_is_waiting_for_100_continue:
                self.send(h11.InformationalResponse(status_code=100))
            return False

        if event is h11.PAUSED:
            # Still waiting for previous response, apply backpressure
            self.transport.pause_reading()
            return False

        raise RuntimeError('Unknown HTTP event', event)

    def handle_task_result(self, task):
        res = task.result()
        headers = [('content-type', 'application/json'),
                   ('content-length', str(len(res)))]
        response = h11.Response(status_code=200, headers=headers)
        self.send(response)
        self.send(h11.Data(data=res.encode('utf-8')))
        self.send(h11.EndOfMessage())

        if self.connection.our_state == h11.DONE and self.connection.their_state == h11.DONE:
            self.connection.start_next_cycle()
            self.deliver_events()
            self.transport.resume_reading()

    def send(self, event):
        data = self.connection.send(event)
        self.transport.write(data)


def main():
    make_block(None)

    d = ajsonrpc.dispatcher.Dispatcher()
    d['eth_sendTransaction'] = send_tx
    d['eth_call'] = call
    d['eth_chainId'] = chain_id
    d['eth_getBlockByNumber'] = get_block
    d['eth_getTransactionCount'] = tx_count
    d['eth_estimateGas'] = estimate_gas
    d['eth_blockNumber'] = block_number
    d['eth_sendRawTransaction'] = send_raw_transaction
    d['eth_getTransactionReceipt'] = get_tx_receipt
    d['web3_clientVersion'] = client_version
    d['eth_gasPrice'] = gas_price
    d['eth_getTransactionByHash'] = get_tx
    d['net_version'] = chain_id
    d['eth_getCode'] = get_code
    d['eth_getBalance'] = get_balance
    d['eth_accounts'] = accounts
    d['eth_getLogs'] = get_logs

    json_rpc_manager = ajsonrpc.manager.AsyncJSONRPCResponseManager(
        dispatcher=d, is_server_error_verbose=True)
    # Each client connection will create a new protocol instance
    coro = loop.create_server(
        lambda: JSONRPCProtocol(json_rpc_manager),
        host=listen_host,
        port=listen_port
    )
    server = loop.run_until_complete(coro)
    loop.create_task(do_recv())

    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    writer.close()
    loop.run_until_complete(writer.wait_closed())
    loop.close()


if __name__ == '__main__':
    main()
