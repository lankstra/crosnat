import socket
import ssl
import sys
import time
import threading
import logging
import protocol
from enum import Enum


class State(Enum):
    INIT = 1
    WAIT = 2
    TRANSFER = 3


class Phase(Enum):
    AUTH = 1
    PROXY = 2
    PRIVATE = 3


logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                    datefmt='%Y/%m/%d %H:%M:%S')

ctrl_sock = 0
client_id = ''

BUFF_SIZE = 1024
revserv_server = '127.0.0.1'
revserv_port = 9090

tunnels = list()
body = dict()
body['rport'] = 55499
body['lhost'] = '127.0.0.1'
body['lport'] = 7070
tunnels.append(body)

body = dict()
body['rport'] = 55488
body['lhost'] = '127.0.0.1'
body['lport'] = 22
tunnels.append(body)


def connect_server(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(sock, ca_certs='./mycertfile.pem', cert_reqs=ssl.CERT_REQUIRED)
        ssl_sock.connect((ip, port))
        ssl_sock.setblocking(1)
    except socket.error:
        return None
    return ssl_sock


def connect_local(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
    except socket.error:
        return False
    return sock


def client_handle(sock, phase, state=State.INIT, to_sock=None):
    logging.info('client_handle, %s, %s' % (phase, state))
    global ctrl_sock
    global client_id
    recv_buff = bytes()
    while True:
        try:
            if state == State.INIT:
                if phase == Phase.AUTH:
                    protocol.send_packet(sock, protocol.auth())
                    logging.info('sent auth to revserv_server %s' % sock.getpeername()[0])
                    state = State.WAIT
                    logging.info('client_handle, %s, change to %s' % (phase, state))

                if phase == Phase.PROXY:
                    protocol.send_packet(sock, protocol.reg_proxy(client_id))
                    logging.info('sent reg_proxy to revserv_server %s' % sock.getpeername()[0])
                    state = State.WAIT
                    logging.info('client_handle, %s, change to %s' % (phase, state))

                if phase == Phase.PRIVATE:
                    state = State.TRANSFER
                    logging.info('client_handle, %s, change to %s' % (phase, state))

            recv_chunk = sock.recv(BUFF_SIZE)
            if not recv_chunk:
                break

            if len(recv_chunk) > 0:
                if not recv_buff:
                    recv_buff = recv_chunk
                else:
                    recv_buff += recv_chunk

            if phase == Phase.AUTH or (phase == Phase.PROXY and state == State.WAIT):
                pack_len = protocol.bytes_to_len(recv_buff[0:8])
                if len(recv_buff) >= pack_len:
                    buff = recv_buff[8:8 + pack_len].decode('utf-8')
                    js = protocol.json.loads(buff)

                    if phase == Phase.AUTH:
                        if js['Type'] == 'AuthResp':
                            client_id = js['Payload']['ClientId']
                            logging.info('recv AuthResp, client_id:%s' % client_id)
                            for tunnel in tunnels:
                                protocol.send_packet(sock, protocol.req_tunnel(tunnel.get('rport')))
                                logging.info('sent ReqTunnel, rport:%s' % tunnel.get('rport'))

                        if js['Type'] == 'NewTunnel':
                            if js['Payload']['Error'] != '':
                                logging.info('recv NewTunnel. Error:%s' % js['Payload']['Error'])
                            else:
                                laddr = protocol.get_local_addr(tunnels, js['Payload']['Rport'])
                                logging.info('recv NewTunnel. Established lport:%s<->rport:%s' %
                                             (laddr.get('lport'), js['Payload']['Rport']))

                        if js['Type'] == 'ReqProxy':
                            proxy_sock = connect_server(revserv_server, revserv_port)
                            logging.info('recv ReqProxy, start proxy connection.')
                            if proxy_sock:
                                thread_proxy = threading.Thread(target=client_handle, args=(proxy_sock, Phase.PROXY))
                                thread_proxy.setDaemon(True)
                                thread_proxy.start()

                    if phase == Phase.PROXY:
                        if js['Type'] == 'StartProxy':
                            logging.info('recv StartProxy, rport:%s' % js['Payload']['Rport'])
                            local_addr = protocol.get_local_addr(tunnels, js['Payload']['Rport'])
                            priv_sock = connect_local(local_addr.get('lhost'), local_addr.get('lport'))
                            if priv_sock:
                                thread_private = threading.Thread(args=(priv_sock, Phase.PRIVATE, State.INIT, sock),
                                                                  target=client_handle)
                                thread_private.setDaemon(True)
                                thread_private.start()
                                state = State.TRANSFER
                                logging.info('client_handle, %s, change to %s' % (phase, state))
                                to_sock = priv_sock

                    if js['Type'] == 'Echo':
                        logging.info('recv echo from %s' % sock.getpeername()[0])
                        protocol.send_packet(sock, protocol.ack())

                    if len(recv_buff) == (pack_len + 8):
                        recv_buff = bytes()
                    else:
                        recv_buff = recv_buff[8 + pack_len:]

            if phase == Phase.PRIVATE or (phase == Phase.PROXY and state == State.TRANSFER):
                protocol.send_buff(to_sock, recv_buff)
                recv_buff = bytes()

        except socket.error as err:
            print("%s %s %s" % (phase, state, err))
            break

    if phase == Phase.AUTH:
        ctrl_sock = False
    if phase == Phase.PRIVATE:
        try:
            to_sock.shutdown(socket.SHUT_WR)
        except socket.error:
            to_sock.close()
    sock.close()


if __name__ == '__main__':
    logging.info('client start')
    while True:
        try:
            if not ctrl_sock:
                ctrl_sock = connect_server(revserv_server, revserv_port)
                if ctrl_sock:
                    logging.info('ctrl connection established')
                    thread = threading.Thread(target=client_handle, args=(ctrl_sock, Phase.AUTH, State.INIT, None))
                    thread.setDaemon(True)
                    thread.start()
                else:
                    logging.info('ctrl sock does not exist')
            time.sleep(1)
        except socket.error as e:
            print(e)
        except KeyboardInterrupt:
            sys.exit()
