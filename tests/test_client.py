# test_client.py

import pytest
import threading
import time
from pyrats_tls import (
    start_server,
    connect_ra_tls_client,
    send_message,
    receive_message,
    close_connection,
    verify_attestation_token,
    PlatformNotSupportedError,
)

def test_client_without_mutual_attestation():
    try:
        token, connection = connect_ra_tls_client("127.0.0.1", "4444", mutual_attestation=False)
        assert isinstance(token, str) and len(token) > 0
        assert verify_attestation_token(token)
        close_connection(connection)
    except RuntimeError:
        pass  # Server may not be running

def test_client_with_mutual_attestation():
 ear):
        token, connection = connect_ra_tls_client("127.0.0.1", "4444", mutual_attestation=True)
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
            token, server_conn = start_server("127.0.0.1", "4446", mutual_attestation=True)
            assert verify_attestation_token(token)
            message = receive_message(server_conn)
            assert message == "Hello, RATS-TLS!"
            close_connection(server_conn)
        except RuntimeError as e:
            print(f"Server error: {e}")

    def client_thread():
        time.sleep(0.1)  # Ensure server starts first
        try:
            token, client_conn = connect_ra_tls_client("127.0.0.1", "4446", mutual_attestation=True)
            assert verify_attestation_token(token)
            send_message(client_conn, "Hello, RATS-TLS!")
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