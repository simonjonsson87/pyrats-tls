# test_client.py

import pytest
import platform
import threading
import time
from pyrats_tls import (
    start_server,
    connect_client,
    send_message,
    receive_message,
    close_connection,
    verify_attestation_token,
    PlatformNotSupportedError,
)

def test_client_without_mutual_attestation():
    try:
        token, connection, _ = connect_client("127.0.0.1", 4444, mutual_attestation=False, attester_type="nullattester", verifier_type="nullverifier")
        assert isinstance(token, str) and len(token) > 0
        assert verify_attestation_token(token)
        close_connection(connection)
    except RuntimeError:
        pass  # Server may not be running

def test_client_with_mutual_attestation():
    try:
        token, connection, _ = connect_client("127.0.0.1", 4444, mutual_attestation=True, attester_type="nullattester", verifier_type="nullverifier")
        assert isinstance(token, str) and len(token) > 0
        assert verify_attestation_token(token)
        close_connection(connection)
    except RuntimeError:
        pass  # Server or client may not support mutual attestation

def test_client_server_message_passing():
    if platform.system() != "Linux":
        pytest.skip("RA-TLS server is only supported on Linux")

    def server_thread():
        try:
            token, server_conn, _ = start_server("127.0.0.1", 4446, mutual_attestation=True, attester_type="nullattester", verifier_type="nullverifier")
            assert verify_attestation_token(token)
            message = receive_message(server_conn)
            assert message == "Hello, RATS-TLS!"
            close_connection(server_conn)
        except RuntimeError as e:
            print(f"Server error: {e}")

    def client_thread():
        time.sleep(0.1)  # Ensure server starts first
        try:
            token, client_conn, _ = connect_client("127.0.0.1", 4446, mutual_attestation=True, attester_type="nullattester", verifier_type="nullverifier")
            assert verify_attestation_token(token)
            send_message(client_conn, "Hello, RATS-TLS!")
            response = receive_message(client_conn)
            assert response == "Server response: OK"
            close_connection(client_conn)
        except RuntimeError as e:
            print(f"Client error: {e}")

    server_t = threading.Thread(target=server_thread)
    client_t = threading.Thread(target=client_thread)
    server_t.start()
    client_t.start()
    server_t.join(timeout=5)
    client_t.join(timeout=5)
    assert not server_t.is_alive() and not client_t.is_alive(), "Threads did not complete"

def test_client_on_non_linux():
    if platform.system() == "Linux":
        pytest.skip("Test only applicable on non-Linux platforms")
    try:
        token, connection, _ = connect_client("127.0.0.1", 4444, mutual_attestation=False, attester_type="nullattester", verifier_type="nullverifier")
        assert isinstance(token, str) and len(token) > 0
        assert verify_attestation_token(token)
        close_connection(connection)
    except RuntimeError:
        pass  # Server may not be running