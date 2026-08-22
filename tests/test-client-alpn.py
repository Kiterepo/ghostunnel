#!/usr/bin/env python3

"""
Tests that ghostunnel in client mode respects the --alpn flag by verifying that:
1. The offered protocols are negotiated against a backend that supports them
2. Server preference on the backend decides which one is picked
3. Whitespace around entries in the flag value is trimmed
"""

from common import SocketPair, TcpClient, TlsServer, create_default_certs, \
    print_ok, start_ghostunnel_client, terminate, LISTEN_PORT, TARGET_PORT

ghostunnel = None
pair = None
root = None
try:
    root = create_default_certs()

    # Note the deliberate whitespace after the comma: it must be trimmed, or
    # ghostunnel would offer " http/1.1" and the backend would never match it.
    ghostunnel = start_ghostunnel_client(extra_args=['--alpn=h2, http/1.1'])

    print_ok("testing that ghostunnel offers the configured protocols...")
    # The backend lists http/1.1 first and server preference wins, so http/1.1
    # must be selected even though ghostunnel lists h2 first. That only works
    # if ghostunnel actually offered a well-formed "http/1.1".
    pair = SocketPair(TcpClient(LISTEN_PORT),
                      TlsServer('server', 'root', TARGET_PORT,
                                alpn=['http/1.1', 'h2']))
    selected = pair.server.selected_alpn_protocol()
    if selected != 'http/1.1':
        raise Exception(
            "expected backend to negotiate http/1.1, got {0}".format(selected))
    pair.validate_can_send_from_client("hello world", "client -> server")
    pair.validate_can_send_from_server("hello world", "server -> client")
    pair.cleanup()
    pair = None
    print_ok("negotiated http/1.1 (whitespace in --alpn was trimmed)")

    print_ok("testing backend that only supports h2...")
    pair = SocketPair(TcpClient(LISTEN_PORT),
                      TlsServer('server', 'root', TARGET_PORT, alpn=['h2']))
    selected = pair.server.selected_alpn_protocol()
    if selected != 'h2':
        raise Exception(
            "expected backend to negotiate h2, got {0}".format(selected))
    pair.cleanup()
    pair = None
    print_ok("negotiated h2")

    # Rejection of a malformed --alpn value at startup is covered by
    # test-invalid-client-flags.py.

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if pair:
        pair.cleanup()
    if root:
        root.cleanup()
