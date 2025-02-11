#!/usr/bin/env python3

"""
Ensures when server disconnects that the client connection also disconnects, with UNIX sockets.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, UnixServer, TlsClient, print_ok, run_ghostunnel, terminate

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel
        server = UnixServer()
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target=unix:{0}'.format(server.get_socket_path()),
                                     '--keystore=server.p12',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--cacert=root.crt',
                                     '--allow-ou=client'])

        # connect with client, confirm that the tunnel is up
        pair = SocketPair(TlsClient('client', 'root', 13001), server)
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_closing_server_closes_client(
            "1: server closed -> client closed")

        pair = SocketPair(TlsClient('client', 'root', 13001), server)
        pair.validate_can_send_from_server(
            "hello world", "2: server -> client")
        pair.validate_can_send_from_client(
            "hello world", "2: client -> server")
        pair.validate_half_closing_server_closes_client(
            "2: server closed -> client closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
