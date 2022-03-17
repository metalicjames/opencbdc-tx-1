import socket
import struct
import jsonrpclib.SimpleJSONRPCServer as rpc
import random
import transaction
import wire

HOST = ''
PORT = 6666
LISTEN_HOST = ''
LISTEN_PORT = 8080

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

def serialize_exec(func_key, params, dry_run):
    ret = bytes()

    ret += struct.pack('Q', len(func_key))
    ret += func_key

    ret += struct.pack('Q', len(params))
    ret += params

    ret += struct.pack('?', dry_run)

    return ret

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

    print('Sending:', req.hex())

    sock.sendall(req)

    return recv_data(req_id)

def send_transaction(param):
    tx = transaction.Transaction.from_json(param)
    exec_req = wire.Request(tx.from_addr, tx.pack(), False)
    resp = send_req(exec_req.pack())

    print(resp)
    r = wire.Response.unpack(resp)
    if r.success is not None:
        receipt_buf = r.success[tx.txid()]
        if receipt_buf is None:
            raise ValueError('Invalid response')
        receipt = transaction.Receipt.unpack(receipt_buf)
        return receipt

    return r.failure


def main():
    server = rpc.SimpleJSONRPCServer((LISTEN_HOST, LISTEN_PORT))
    server.register_function(send_transaction, 'eth_sendTransaction')
    server.serve_forever()

if __name__ == '__main__':
    main()

