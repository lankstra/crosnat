import socket
import ssl
import sys
import json
import threading
import logging
import time
import random
from queue import Queue
import protocol

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                    datefmt='%Y/%m/%d %H:%M:%S')

global_config = dict()
global_config['keyfile'] = 'mykeyfile.pem'
global_config['certfile'] = 'mycertfile.pem'
global_config['username'] = 'secret'
global_config['password'] = 'secret'
global_config['revserv_server'] = '127.0.0.1'
global_config['revserv_port'] = 9090

BUFF_SIZE = 1024
ctrl_sock = None
auth_tab = dict()
tunnels_tab = dict()
client_reglist = dict()
public_reglist = dict()


def _cross_nat_accept(sock, handle_func):
    try:
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=handle_func, args=(conn, addr)).start()
    except socket.error:
        logging.info('listen_sock closed')
    except KeyboardInterrupt:
        sys.exit()


def _cross_nat_listen(host, port, is_ssl, is_keepalive):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if is_keepalive:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.bind((host, port))
    sock.listen(5)
    if is_ssl:
        ssl_sock = ssl.wrap_socket(sock, keyfile=global_config.get('keyfile'), certfile=global_config.get('certfile'),
                                   server_side=True)
        return ssl_sock
    return sock


def cross_nat_run(host, port, is_ssl, is_keepalive, handle_func):
    try:
        sock = _cross_nat_listen(host, port, is_ssl, is_keepalive)
        thread = threading.Thread(target=_cross_nat_accept, args=(sock, handle_func))
        thread.setDaemon(True)
        thread.start()
        return sock
    except socket.error as e:
        print(e)
    return None


def parse_reqtunnel(js_buff, conn, client_id):
    if 'Payload' in js_buff:
        rport = js_buff['Payload'].get('Rport', random.randint(1024, 65535))
        error = 'the tunnel for rport=%s is already registered' % str(rport)
        logging.info('recv reqtunnel, rport=%s' % str(rport))

        if rport in client_reglist:
            protocol.send_packet(conn, protocol.new_tunnel(error=error))
            conn.shutdown(socket.SHUT_WR)
            logging.info('recv reqtunnel but already registered, rport=%s' % str(rport))
            return False

        logging.info('listening rport=%s' % str(rport))
        try:
            listen_sock = cross_nat_run('', rport, False, False, service_to_public)
        except socket.error as e:
            logging.info('recv reqtunnel ', e)
            protocol.send_packet(conn, protocol.new_tunnel(error=error))
            return False
        info = dict()
        info['ctrl_sock'] = conn
        info['client_id'] = client_id
        info['listen_sock'] = listen_sock
        client_reglist[rport] = info
        tunnels_tab[client_id].append(rport)

        protocol.send_packet(conn, protocol.new_tunnel(js_buff['Payload']['ReqId'], rport))
        return True


def parse_regproxy(js_buff, conn):
    client_id = ''

    if 'Payload' in js_buff:
        client_id = js_buff['Payload'].get('ClientId')
    if not (client_id in public_reglist):
        return None
    info = public_reglist[client_id].get()
    if not info:
        return None
    pub_sock = info['public_sock']
    rport = info['rport']
    sock_info = pub_sock.getpeername()
    pub_addr = sock_info[0] + ':' + str(sock_info[1])
    logging.info('recv Regproxy, pack_clientid:%s, public_addr:%s' % (client_id, pub_addr))
    protocol.send_packet(conn, protocol.start_proxy(rport, client_addr=pub_addr))
    info['queue'].put(conn)
    return pub_sock


def service_to_public(conn, addr):
    logging.info('service to public from addr:%s' % str(addr))
    proxy_sock = None

    while True:
        try:
            chunk = conn.recv(BUFF_SIZE)
            if not chunk:
                break

            if not proxy_sock:
                rport = conn.getsockname()[1]

                if rport in client_reglist:
                    logging.info('public conn come in, rport=%s found in reg_client.' % str(rport))
                    info = client_reglist[rport]
                    protocol.send_packet(info['ctrl_sock'], protocol.req_proxy())

                    reg_info = dict()
                    reg_info['rport'] = rport
                    reg_info['public_sock'] = conn
                    reg_info['queue'] = Queue()

                    public_reglist[info['client_id']].put(reg_info)
                    proxy_sock = reg_info['queue'].get()

            if proxy_sock:
                protocol.send_buff(proxy_sock, chunk)

        except socket.error as e:
            logging.info('public peer close')
            break


def service_to_ctrl_channel(conn, addr):
    logging.info('service to ctrl channel, addr:%s' % str(addr))
    global tunnels_tab
    public_sock = None
    client_id = ''
    recv_buff = bytes()
    while True:
        try:
            chunk = conn.recv(BUFF_SIZE)
            if not chunk:
                break

            if len(chunk) > 0:
                if not recv_buff:
                    recv_buff = chunk
                else:
                    recv_buff += chunk

            if len(recv_buff) < 8:
                continue

            pack_len = protocol.bytes_to_len(recv_buff[:8])
            if len(recv_buff) >= (pack_len + 8):
                str_buff = recv_buff[8: 8 + pack_len].decode('utf-8')
                js_buff = json.loads(str_buff)
                pack_type = js_buff.get('Type')

                ip, _ = conn.getpeername()
                if pack_type == 'Auth' and 'Payload' in js_buff:
                    if js_buff['Payload'].get('User') == global_config['username'] and \
                       js_buff['Payload'].get('Password') == global_config['password']:
                        client_id = protocol.get_str_md5(str(time.time()))
                        tunnels_tab[client_id] = list()
                        public_reglist[client_id] = Queue()
                        auth_tab[ip] = True
                        protocol.send_packet(conn, protocol.auth_resp(client_id=client_id))
                    else:
                        auth_tab[ip] = False
                        logging.info('auth failed1')
                        break
                else:
                    if ip not in auth_tab or not auth_tab[ip]:
                        logging.info('auth failed2')
                        break

                if pack_type == 'ReqTunnel':
                    parse_reqtunnel(js_buff, conn, client_id)
                if pack_type == 'RegProxy':
                    sock = parse_regproxy(js_buff, conn)
                    if sock:
                        public_sock = sock

                if len(recv_buff) == (8 + pack_len):
                    recv_buff = bytes()
                else:
                    recv_buff = recv_buff[8 + pack_len:]

            if public_sock:
                protocol.send_buff(public_sock, recv_buff)
                recv_buff = bytes()

        except Exception as e:
            logging.info(e)
            break

    if public_sock:
        public_sock.close()

    if client_id in public_reglist:
        del public_reglist[client_id]

    if client_id in tunnels_tab:
        for port in tunnels_tab[client_id]:
            if port in client_reglist:
                listen_sock = client_reglist[port].get('listen_sock')
                if listen_sock:
                    listen_sock.close()
                del client_reglist[port]
        del tunnels_tab[client_id]
    logging.info('close peer %s:%s' % (conn.getpeername()[0], conn.getpeername()[1]))
    conn.close()


if __name__ == '__main__':
    logging.info('server start')
    cross_nat_run('', global_config['revserv_port'], True, True, service_to_ctrl_channel)

    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            sys.exit()
