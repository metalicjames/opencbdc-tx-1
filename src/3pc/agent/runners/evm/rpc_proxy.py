import socket
import struct
import jsonrpclib.SimpleJSONRPCServer as rpc
import random

HOST = ''
PORT = 5000
LISTEN_HOST = ''
LISTEN_PORT = 8080

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

def serialize_transaction(tx):
    ret = bytes()

    from_addr = bytes.fromhex(tx['from'])
    ret += from_addr

    has_to = 'to' in tx
    ret += struct.pack('?', has_to)
    if has_to:
        to_addr = bytes.fromhex(tx['to'])
        ret += to_addr

    value = bytes.fromhex(tx['value'])
    ret += bytearray(32 - len(value)) + value

    nonce = bytes.fromhex(tx['nonce'])
    ret += bytearray(32 - len(nonce)) + nonce

    gas_price = bytes.fromhex(tx['gasPrice'])
    ret += bytearray(32 - len(gas_price)) + gas_price

    gas = bytes.fromhex(tx['gas'])
    ret += bytearray(32 - len(gas)) + gas

    if 'input' in tx:
        inp = bytes.fromhex(tx['input'])
        ret += struct.pack('Q', len(inp))
        ret += inp

    return ret

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
    req_id = struct.unpack('Q', resp_dat[:8])[0]
    assert req_id == id

    return resp_dat[8:]

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
    tx = serialize_transaction(param)
    from_addr = bytes.fromhex(param['from'])
    exec_req = serialize_exec(from_addr, tx, False)
    resp = send_req(exec_req)
    # TODO: deserialize response
    return resp


def main():
    server = rpc.SimpleJSONRPCServer((LISTEN_HOST, LISTEN_PORT))
    server.register_function(send_transaction, 'eth_sendTransaction')
    server.serve_forever()

if __name__ == '__main__':
    main()

