#!/usr/bin/env python3

"""
Ensures ghostunnel in client mode can connect to a unix socket target.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsUnixServer, print_ok, run_ghostunnel, require_platform, terminate, LISTEN_PORT

require_platform('Darwin', 'Linux', 'BSD')

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    server = TlsUnixServer('server', 'root')
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target=unix:{0}'.format(server.get_socket_path()),
                                 '--override-server-name=server',
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # connect with client, confirm that the tunnel is up
    pair = SocketPair(TcpClient(LISTEN_PORT), server)
    server.validate_client_cert('client')
    pair.validate_can_send_from_client(
        "hello world", "1: client -> server")
    pair.validate_can_send_from_server(
        "hello world", "1: server -> client")
    pair.validate_closing_client_closes_server(
        "1: client closed -> server closed")

    print_ok("OK")
finally:
    terminate(ghostunnel)
