import json
import struct


def len_to_bytes(length):
    return struct.pack('<LL', length, 0)


def bytes_to_len(b):
    if len(b) == 8:
        return struct.unpack('<LL', b)[0]
    return 0


def send_buff(sock, buff):
    sock.sendall(buff)


def send_packet(sock, packet):
    sock.sendall(len_to_bytes(len(packet)))
    sock.sendall(packet.encode('utf-8'))


def get_random_str(length):
    import random
    _chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz'
    return ''.join(random.sample(_chars, length))


def get_str_md5(s):
    import hashlib
    return hashlib.md5(s.encode('utf-8')).hexdigest().lower()


def auth():
    payload = dict()
    payload['ClientId'] = ''
    payload['User'] = 'secret'
    payload['Password'] = 'secret'
    body = dict()
    body['Type'] = 'Auth'
    body['Payload'] = payload
    buff = json.dumps(body)
    return buff


def auth_resp(client_id='', version='1', error=''):
    payload = dict()
    payload['ClientId'] = client_id
    payload['Version'] = version
    payload['Error'] = error
    body = dict()
    body['Type'] = 'AuthResp'
    body['Payload'] = payload
    buff = json.dumps(body)
    return buff


def req_tunnel(remote_port):
    payload = dict()
    payload['ReqId'] = get_random_str(8)
    payload['Rport'] = remote_port
    body = dict()
    body['Type'] = 'ReqTunnel'
    body['Payload'] = payload
    buff = json.dumps(body)
    return buff


def new_tunnel(request_id='', rport='', protocol='', error=''):
    payload = dict()
    payload['ReqId'] = request_id
    payload['Rport'] = rport
    payload['Protocol'] = protocol
    payload['Error'] = error
    body = dict()
    body['Type'] = 'NewTunnel'
    body['Payload'] = payload
    buff = json.dumps(body)
    return buff


def req_proxy():
    payload = dict()
    body = dict()
    body['Type'] = 'ReqProxy'
    body['Payload'] = payload
    buff = json.dumps(body)
    return buff


def reg_proxy(client_id):
    payload = dict()
    payload['ClientId'] = client_id
    body = dict()
    body['Type'] = 'RegProxy'
    body['Payload'] = payload
    buff = json.dumps(body)
    return buff


def start_proxy(rport, client_addr):
    payload = dict()
    body = dict()
    payload['Rport'] = rport
    payload['ClientAddr'] = client_addr
    body['Type'] = 'StartProxy'
    body['Payload'] = payload
    buff = json.dumps(body)
    return buff


def get_local_addr(tunnels, rport):
    for tunnel in tunnels:
        if tunnel.get('rport') == int(rport):
            return tunnel
    return dict()
