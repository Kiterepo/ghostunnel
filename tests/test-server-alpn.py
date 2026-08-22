#!/usr/bin/env python3

"""
Tests that ghostunnel in server mode respects the --alpn flag by verifying that:
1. A client offering a supported protocol negotiates it
2. Server preference order wins when the client offers several protocols
3. Whitespace around entries in the flag value is trimmed
4. A client offering no ALPN at all still connects
5. A client with no protocol in common is rejected
"""

import ssl

from common import STATUS_PORT, TlsClient, TcpServer, create_default_certs, \
    print_ok, start_ghostunnel_server, terminate, LISTEN_PORT, TARGET_PORT

ghostunnel = None
backend = None
root = None
try:
    root = create_default_certs()

    # Note the deliberate whitespace after the comma: it must be trimmed, or
    # ghostunnel would advertise " http/1.1" and never match a real client.
    ghostunnel = start_ghostunnel_server(extra_args=['--alpn=h2, http/1.1'])

    # Wait for startup
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

    # Create backend socket
    backend = TcpServer(TARGET_PORT)
    backend.listen()

    print_ok("testing client offering http/1.1 only...")
    client = TlsClient('client', 'root', LISTEN_PORT, alpn=['http/1.1'])
    client.connect()
    selected = client.selected_alpn_protocol()
    if selected != 'http/1.1':
        raise Exception(
            "expected to negotiate http/1.1, got {0}".format(selected))
    client.cleanup()
    print_ok("negotiated http/1.1 (whitespace in --alpn was trimmed)")

    print_ok("testing server preference order...")
    # The client lists http/1.1 first, but the server lists h2 first and server
    # preference wins, so h2 must be selected.
    client = TlsClient('client', 'root', LISTEN_PORT, alpn=['http/1.1', 'h2'])
    client.connect()
    selected = client.selected_alpn_protocol()
    if selected != 'h2':
        raise Exception(
            "expected server preference to select h2, got {0}".format(selected))
    client.cleanup()
    print_ok("negotiated h2 (server preference order wins)")

    print_ok("testing client that doesn't offer ALPN...")
    # Setting NextProtos on a server doesn't require clients to use ALPN; a
    # client that omits the extension entirely still connects.
    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect()
    selected = client.selected_alpn_protocol()
    if selected is not None:
        raise Exception(
            "expected no negotiated protocol, got {0}".format(selected))
    client.cleanup()
    print_ok("connected without ALPN")

    print_ok("testing client with no protocol in common...")
    # The client must NOT offer "http/1.1" here: crypto/tls has a special case
    # (Go issue 46310) where a server offering "h2" accepts an http/1.1-only
    # client as if ALPN were absent, which would make this case pass for the
    # wrong reason.
    client = TlsClient('client', 'root', LISTEN_PORT, alpn=['postgresql'])
    err = None
    try:
        client.connect()
    except Exception as e:
        err = e
    if err is None:
        raise Exception(
            "expected connection with no shared ALPN protocol to fail, "
            "but it succeeded")
    # Any cert or config problem would also fail the connect; make sure it
    # failed for the right reason by checking for the alert on the chained
    # underlying error. Some OpenSSL builds have no error-string entry for
    # the no_application_protocol alert and report it as "unknown error";
    # accept that too, since cert/config failures always have named reasons.
    cause = str(err.__cause__).upper()
    if not isinstance(err.__cause__, ssl.SSLError) or (
            'NO_APPLICATION_PROTOCOL' not in cause
            and 'UNKNOWN ERROR' not in cause):
        raise Exception(
            "expected a no_application_protocol alert, got: {0!r}".format(
                err.__cause__)) from err
    client.cleanup()
    print_ok("connection rejected as expected (no_application_protocol)")

    # Rejection of a malformed --alpn value at startup is covered by
    # test-invalid-client-flags.py.

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if backend:
        backend.cleanup()
    if root:
        root.cleanup()
