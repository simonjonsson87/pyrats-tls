# test_load_native.py

import pytest
import socket
import threading
import time
import platform
from pyrats_tls import (
    start_server,
    connect_client,
    send_message,
    receive_message,
    close_connection,
    PlatformNotSupportedError,
    RatsTlsError,
)

# Constants for testing
TEST_IP = "127.0.0.1"
TEST_PORT = 12345  # Use a high port to avoid конфликts
TIMEOUT = 2  # Seconds for connection attempts

@pytest.fixture
def server():
    """Start a RATS-TLS server and yield its handle and claims."""
    if platform.system() != "Linux":
        pytest.skip("RA-TLS server is only supported on Linux")
    try:
        handle, claims, _ = start_server(
            ip=TEST_IP,
            port=TEST_PORT,
            attester_type="nullattester",
            verifier_type="nullverifier",
            mutual_attestation=False,
            provide_endorsements=False,
            log_level="debug"
        )
        time.sleep(0.1)
        yield handle, claims
    finally:
        close_connection(handle)

@pytest.fixture
def client():
    """Start a RATS-TLS client and yield its handle and claims."""
    handle, claims, _ = connect_client(
        ip=TEST_IP,
        port=TEST_PORT,
        attester_type="nullattester",
        verifier_type="nullverifier",
        mutual_attestation=False,
        log_level="debug"
    )
    try:
        yield handle, claims
    finally:
        close_connection(handle)

def test_server_starts_successfully(server):
    """Test that the server starts without errors."""
    handle, _ = server
    assert handle is not None, "Server handle should be valid"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        result = s.connect_ex((TEST_IP, TEST_PORT))
        assert result == 0, "Server should be accepting connections"

def test_client_connects_successfully(server, client):
    """Test that the client connects to the server."""
    client_handle, _ = client
    assert client_handle is not None, "Client handle should be valid"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        result = s.connect_ex((TEST_IP, TEST_PORT))
        assert result == 0, "Server should still be accepting connections after client connects"

def test_message_exchange(server, client):
    """Test sending and receiving messages between client and server."""
    client_handle, _ = client
    test_message = "Hello, RATS-TLS!"
    send_message(client_handle, test_message)
    response = receive_message(client_handle)
    assert response == "Server response: OK", f"Expected server response, got {response}"

def test_empty_message(server, client):
    """Test sending an empty message."""
    client_handle, _ = client
    send_message(client_handle, "")
    response = receive_message(client_handle)
    assert response == "Server response: OK", "Empty message should still get server response"

def test_invalid_port():
    """Test starting a server on an invalid port."""
    if platform.system() != "Linux":
        pytest.skip("RA-TLS server is only supported on Linux")
    with pytest.raises(RatsTlsError, match="Failed to create socket"):
        start_server(ip=TEST_IP, port=0)  # Port 0 is invalid

def test_port_in_use():
    """Test starting a server on a port already in use."""
    if platform.system() != "Linux":
        pytest.skip("RA-TLS server is only supported on Linux")
    dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dummy_sock.bind((TEST_IP, TEST_PORT))
    dummy_sock.listen(1)
    try:
        with pytest.raises(RatsTlsError, match="Failed to create socket"):
            start_server(ip=TEST_IP, port=TEST_PORT)
    finally:
        dummy_sock.close()

def test_connect_to_nonexistent_server():
    """Test connecting to a server that doesn't exist."""
    with pytest.raises(RatsTlsError, match="Client connection failed"):
        connect_client(ip=TEST_IP, port=TEST_PORT + 1)

def test_invalid_attester_type():
    """Test using an invalid attester type."""
    if platform.system() != "Linux":
        pytest.skip("RA-TLS server is only supported on Linux")
    with pytest.raises(RatsTlsError, match="Failed to initialize RATS-TLS"):
        start_server(attester_type="invalid_attester", verifier_type="nullverifier")

def test_close_connection_invalid_handle():
    """Test closing an invalid or null handle."""
    close_connection(None)  # Should not raise or crash
    if platform.system() != "Linux":
        pytest.skip("RA-TLS server is only supported on Linux")
    handle, _, _ = start_server(ip=TEST_IP, port=TEST_PORT + 1)
    close_connection(handle)
    close_connection(handle)  # Should not crash

@pytest.mark.skipif(platform.system() != "Linux", reason="SEV-SNP requires Linux and specific hardware")
def test_sev_snp_attester():
    """Test starting a server with SEV-SNP attester (Linux only)."""
    try:
        handle, _, _ = start_server(
            ip=TEST_IP,
            port=TEST_PORT + 2,
            attester_type="sev_snp",
            verifier_type="sev_snp",
            mutual_attestation=True,
            provide_endorsements=True
        )
        assert handle is not None, "SEV-SNP server handle should be valid"
    except RatsTlsError as e:
        assert "Failed to initialize RATS-TLS" in str(e)

if __name__ == "__main__":
    pytest.main(["-v", __file__])