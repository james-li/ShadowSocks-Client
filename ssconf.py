#!/usr/bin/env python2

# -*- coding: utf-8 -*-
import sys

# try:
#     if 'threading' in sys.modules:
#         raise ImportError('threading module loaded before patching!')
#     import gevent
#     import gevent.monkey
#
#     gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
# except ImportError:
#     gevent = None
#     print >> sys.stderr, 'warning: gevent not found, using threading instead'

from multiprocessing import Queue
from multiprocessing.pool import Pool
import argparse

import socket
import struct
import traceback
import SocketServer
import select

import socks
from sockshandler import SocksiPyHandler

import encrypt

import time
import urllib2
import json
import base64
import logging

import threading

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+', stream=sys.stderr)

LOCAL = "0.0.0.0"
PORT = 1080


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

    def __init__(self, RequestHandlerClass, config):
        SocketServer.TCPServer.__init__(self, (config.get("local"), config.get("local_port")), RequestHandlerClass)
        self.config = config


class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = self.encrypt(sock.recv(4096))
                    if len(data) <= 0:
                        break
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:
                    data = self.decrypt(remote.recv(4096))
                    if len(data) <= 0:
                        break
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        KEY = self.server.config.get("password")
        METHOD = self.server.config.get("method")
        REMOTE_PORT = self.server.config.get("server_port")
        SERVER = self.server.config.get("server")
        try:
            self.encryptor = encrypt.Encryptor(KEY, METHOD)
            sock = self.connection
            sock.recv(262)
            sock.send("\x05\x00")
            data = self.rfile.read(4) or '\x00' * 4
            mode = ord(data[1])
            if mode != 1:
                logging.warn('mode != 1')
                return
            addrtype = ord(data[3])
            addr_to_send = data[3]
            if addrtype == 1:
                addr_ip = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:
                addr_len = self.rfile.read(1)
                addr = self.rfile.read(ord(addr_len))
                addr_to_send += addr_len + addr
            elif addrtype == 4:
                addr_ip = self.rfile.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
                addr_to_send += addr_ip
            else:
                logging.warn('addr_type not support')
                # not support
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port
            port = struct.unpack('>H', addr_port)
            try:
                reply = "\x05\x00\x00\x01"
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)
                self.wfile.write(reply)
                # reply immediately
                remote = socket.create_connection((SERVER, REMOTE_PORT))
                self.send_encrypt(remote, addr_to_send)
                logging.debug('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)


def b64decode(s):
    return base64.urlsafe_b64decode(s + '=' * ((len(s) + 3) / 4 * 4 - len(s)))


def readconf_pgfast(url):
    try:
        raw_content = base64.b64decode(urllib2.urlopen(url).read()).split('\n')
    except Exception as e:
        print("fetch data failed" + str(e))
    conf_json = {
        "shareOverLan": True,
        "localPort": 1080,
        "configs": []
    }
    for ssr_url in raw_content[1:]:
        try:
            server_config = dict()
            tokens = [b64decode(x) for x in ssr_url[len("ssr://"):].split('_')[0:2]]
            server_config["server"], server_config["server_port"], _, server_config["method"], _, server_config[
                "password"] = tokens[0].split(':')
            server_config["password"] = b64decode(server_config["password"].strip('/'))
            server_config["server_port"] = int(server_config["server_port"])
            server_config["remarks"] = b64decode(tokens[1].split('&')[1].split("=")[1])
            # print(server_config)
            conf_json["configs"].append(server_config)
        except:
            continue
    # json.dump(conf_json, sys.stdout, indent=2, ensure_ascii=False)
    return conf_json


def start_server(server):
    try:
        # server = servers[0]
        logging.info("start server at %s:%d" % tuple(server.server_address[:2]))
        server.serve_forever()
    except Exception as e:
        traceback.print_exc()
        return


def test_server1():
    url = "https://www.youtube.com"
    pstr = "http://127.0.0.1:8118"
    proxy = urllib2.ProxyHandler({'http': pstr, 'https': pstr})
    opener = urllib2.build_opener(proxy)
    request = urllib2.Request(url)
    request.add_header('Pragma', 'no-cache')
    for retry in range(1, 4):
        st = time.time()
        try:
            d = opener.open(request, timeout=retry * 3)
            content = d.read()
            # print(content)
            if not content:
                continue
        except:
            # traceback.print_exc()
            continue
        et = time.time()
        return et - st
    return -1


def test_server(port):
    opener = urllib2.build_opener(SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, 'localhost', port))
    try:
        st = time.time()
        content = opener.open("https://www.youtube.com", timeout=10).read()
        if not content:
            return -1
        else:
            return time.time() - st
    except:
        return -1


def test_proxy(conf):
    global confs_filtered
    KEY = conf.get("password")
    METHOD = conf.get("method")
    REMOTE_PORT = conf.get("server_port")
    SERVER = conf.get("server")
    if not (KEY and METHOD and REMOTE_PORT and SERVER):
        return False
    logging.debug("start test server %s %s" % (conf.get("remarks"), conf.get("server")))
    server = ThreadingTCPServer(Socks5Server, conf)
    # server.serve_forever()
    # return
    t = threading.Thread(target=start_server, args=[server])
    t.start()
    # t.join()
    time.sleep(5)
    ret = test_server(conf.get("local_port"))
    server.server_close()
    server.shutdown()
    t.join()
    if ret > 0:
        logging.info("test server %s %s successed, latency %.2f" % (conf.get("remarks"), conf.get("server"), ret))
        confs_filtered.put(conf)
        return True
    else:
        logging.info("test server %s %s failed" % (conf.get("remarks"), conf.get("server")))
        return False


# def filter_proxy():
def filter_proxy(conf_json):
    # conf_json = makeconf(url)
    global LOCAL, PORT
    global confs_filtered
    if not conf_json and not conf_json.get("configs"):
        return
    confs = conf_json.get("configs")
    logging.info("Start to test %d servers"%(len(confs)))
    confs_filtered = Queue()
    i = 0
    for conf in confs:
        i += 1
        conf["local"] = LOCAL
        conf["local_port"] = PORT + i
    pool = Pool(10)
    pool.map(test_proxy, confs)
    #pool.join()
    conf_json["configs"] = []
    while not confs_filtered.empty():
        conf_json["configs"].append(confs_filtered.get())
    json.dump(conf_json, sys.stdout, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse ss config")
    parser.add_argument('--pgfast', help="parse url from pgfast")
    parser.add_argument('--conf', help="parse gui-config.json")
    args = parser.parse_args()
    conf_json = {}
    if args.conf:
        try:
            conf_json = json.load(open(args.conf))
        except:
            pass
    elif args.pgfast:
        url = args.pgfast
        conf_json = readconf_pgfast(url)
    if not conf_json:
        sys.exit(-1)

    filter_proxy(conf_json)
