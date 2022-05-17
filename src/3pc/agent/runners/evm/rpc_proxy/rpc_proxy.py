from cgi import print_exception
import struct
import random
import asyncio
import ajsonrpc
import h11
import argparse
import transaction
import wire
import time
import serialization
import chainparams
import rlp
import ecdsa
import sha3
import eth_utils
import account
import traceback

receipts = {}
blocks = []
blk_hashes = {}
contract_code = {}

requests = {}


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
reader = None
writer = None


async def connect(agent_host, agent_port):
    return await asyncio.open_connection(agent_host, agent_port)


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

    print('writing req')

    writer.write(req)
    await writer.drain()

    print('awaiting recv')
    res = await recv_data(fut, req_id)
    return res


async def send_transaction(tx, dry_run):
    exec_req = wire.Request(b'\2' if dry_run else b'\0', tx.pack(dry_run), dry_run)
    print('awaiting send')
    (success, resp) = await send_req(exec_req.pack())
    if not success:
        raise RuntimeError('RPC request failed')
    print('got resp in send')

    r = wire.Response.unpack(resp)
    if r.success is not None:
        print('success!')
        if tx.txid() not in r.success:
            raise ValueError('Did not find receipt for txid {} in response'.format(tx.txid()))

        receipt_buf = r.success[tx.txid()]
        (receipt, _) = transaction.Receipt.unpack(receipt_buf)
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
    return hex(chainparams.chain_id)

async def read_account(address):
    addr_buf = bytes.fromhex(address[2:])
    exec_req = wire.Request(b'\1', addr_buf, True)
    (success, resp) = await send_req(exec_req.pack())
    if not success:
        raise RuntimeError('RPC request failed')
    r = wire.Response.unpack(resp)
    if r.success is not None:
        account_buf = r.success[addr_buf]
        if account_buf is None:
            raise ValueError('Invalid response')
        (acc, _) = account.Account.unpack(account_buf)
        return acc
    raise RuntimeError(r.failure)

async def read_account_code(address):
    addr_buf = bytes.fromhex(address[2:])
    exec_req = wire.Request(b'\3', addr_buf, True)
    (success, resp) = await send_req(exec_req.pack())
    if not success:
        raise RuntimeError('RPC request failed')
    r = wire.Response.unpack(resp)
    if r.success is not None:
        code_buf = r.success[addr_buf]
        if code_buf is None:
            raise ValueError('Invalid response')

        code_len = struct.unpack('Q', buf[:serialization.UINT64_LEN])[0]
        buf_end = serialization.UINT64_LEN + code_len
        code = code_buf[serialization.UINT64_LEN:buf_end]
        return code
    raise RuntimeError(r.failure)

async def tx_count(address, block):
    assert(block == "pending")
    print('tx_count', address, block)
    account = await read_account(address)
    print('got account, nonce:', account.nonce)
    return hex(account.nonce + 1)

def make_block(txid):
    null_hash = "0x" + bytearray(32).hex()
    if txid is None:
        txid = null_hash
    parent = blocks[-1]['hash'] if len(blocks) > 0 else null_hash
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

    if blk_id == "latest":
        return blocks[-1]

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
    t = transaction.Transaction.unpack_rlp(bytes.fromhex(tx[2:]))
    #print('tx from:', t.from_addr())
    try:
        print('awaiting')
        ret = await send_transaction(t, False)
        print('received receipt:', ret)
        retval = '0x' + t.txid().hex()
        print('txid:', retval)
        make_block(retval)
        print('made block')
        receipts[retval] = ret
        print('stored receipt')
        if ret.create_address is not None:
            contract_code['0x' + ret.create_address.hex()] = ret.output_data
        return retval
    except Exception as e:
        traceback.print_exc()
        raise e


def get_tx_receipt(txid):
    print('get_tx_receipt', txid)
    ret = receipts[txid].to_dict()
    ret['transactionHash'] = txid
    # print(ret)
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
    print('receipt:', r)
    tx = r.tx.to_dict()
    tx['hash'] = txid
    return tx

async def get_code(addr, state):
    print('get_code', addr, state)
    account_code = await read_account_code(addr)
    return '0x' + account.code.hex()

async def get_balance(addr, state):
    print('get_balance', addr, state)
    account = await read_account(addr)
    return serialization.pack_uint256be_hex(account.balance)

def accounts():
    return []

def fee_history(blocks_str, end_block_str, percentiles: list):
    print('fee_history', blocks_str, end_block_str, percentiles)
    hex_str = blocks_str[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    num_blocks = eth_utils.big_endian_to_int(bytes.fromhex(hex_str))
    ret = {}
    pct_count = len(percentiles)
    end_block = len(blocks) if end_block_str == "latest" else int(end_block_str)
    ret["oldestBlock"] = end_block-num_blocks
    ret["reward"] = [["0x0"]*pct_count]*num_blocks
    ret["baseFeePerGas"] = ["0x0"]*(num_blocks+1)
    ret["gasUsedRatio"] = [0.0]*num_blocks
    return ret


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

def increase_time(offset : int):
    # Not supported
    return False

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

        # print('got data', len(data))
        self.connection.receive_data(data)
        self.deliver_events()

    def deliver_events(self):
        more_events = True
        while more_events:
            event = self.connection.next_event()
            more_events = self.handle_event(event)

    def handle_event(self, event) -> bool:
        # print('got HTTP event', type(event))
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

        print('responding with:', res)

        if self.connection.our_state == h11.DONE and self.connection.their_state == h11.DONE:
            self.connection.start_next_cycle()
            self.deliver_events()
            self.transport.resume_reading()

    def send(self, event):
        data = self.connection.send(event)
        self.transport.write(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agent_host', default='127.0.0.1')
    parser.add_argument('--agent_port', type=int, default=6666)
    parser.add_argument('--listen_host', default='0.0.0.0')
    parser.add_argument('--listen_port', type=int, default=8080)
    args = parser.parse_args()
    print('connecting to agent on:',
          args.agent_host + ":" + str(args.agent_port))
    print('rpc proxy listening on:',
          args.listen_host + ":" + str(args.listen_port))

    # TODO: convert this file to a class and remove the globals
    global reader, writer
    reader, writer = loop.run_until_complete(
        connect(args.agent_host, args.agent_port))

    make_block(None)

    d = ajsonrpc.dispatcher.Dispatcher()
    d['eth_sendTransaction'] = send_tx
    d['eth_call'] = call
    d['eth_chainId'] = chain_id
    d['eth_getBlockByNumber'] = get_block
    d['eth_getBlockByHash'] = get_block
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
    d['eth_feeHistory'] = fee_history
    d['evm_increaseTime'] = increase_time

    json_rpc_manager = ajsonrpc.manager.AsyncJSONRPCResponseManager(
        dispatcher=d, is_server_error_verbose=True, )
    # Each client connection will create a new protocol instance
    coro = loop.create_server(
        lambda: JSONRPCProtocol(json_rpc_manager),
        host=args.listen_host,
        port=args.listen_port
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
