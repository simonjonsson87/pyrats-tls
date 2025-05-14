# load_native.py

import ctypes
import os
import sys
import platform
import socket
import threading
import logging

# Set up logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

class RatsTlsError(Exception):
    """Custom exception for RATS-TLS related errors."""
    pass

def _load_library():
    """Load the RATS-TLS library based on the platform."""
    lib_names = {
        "linux": "librats_tls.so",
        "darwin": "librats_tls.dylib",
        "win32": "rats_tls.dll"
    }

    lib_name = lib_names.get(sys.platform)
    if not lib_name:
        raise RatsTlsError(f"Unsupported platform: {sys.platform}")

    # Try package directory first
    package_dir = os.path.dirname(os.path.abspath(__file__))
    lib_path = os.path.join(package_dir, lib_name)
    try:
        if os.path.exists(lib_path):
            return ctypes.CDLL(lib_path)
    except OSError as e:
        print(f"Failed to load {lib_path}: {e}")

    # Fallback to system paths
    try:
        return ctypes.CDLL(lib_name)
    except OSError as e:
        raise RatsTlsError(f"Cannot load {lib_name}: {e}")

# Load RATS-TLS library
lib = _load_library()

# Bind to C free function on the correct library
if sys.platform == "win32":
    libc = ctypes.cdll.msvcrt
elif sys.platform.startswith("linux"):
    libc = ctypes.cdll.LoadLibrary("libc.so.6")
elif sys.platform == "darwin":
    libc = ctypes.cdll.LoadLibrary("libSystem.B.dylib")
else:
    raise RatsTlsError(f"Cannot bind to libc on unsupported platform: {sys.platform}")
libc.free = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(("free", libc))

# Define RATS-TLS handle (opaque)
class RatsTlsHandle(ctypes.Structure):
    pass

# Define RATS-TLS configuration structure
class RatsTlsConf(ctypes.Structure):
    _fields_ = [
        ("log_level", ctypes.c_uint32),
        ("attester_type", ctypes.c_char * 32),
        ("verifier_type", ctypes.c_char * 32),
        ("tls_type", ctypes.c_char * 32),
        ("crypto_type", ctypes.c_char * 32),
        ("flags", ctypes.c_ulong),
        ("cert_algo", ctypes.c_uint32),
        ("custom_claims", ctypes.c_void_p),
        ("custom_claims_length", ctypes.c_size_t),
    ]

# Define claim structure
class Claim(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("value", ctypes.c_void_p),
        ("value_size", ctypes.c_size_t),
    ]

# RATS-TLS constants
RATS_TLS_ERR_NONE = 0
RATS_TLS_LOG_LEVEL_DEBUG = 2
RATS_TLS_LOG_LEVEL_INFO = 3
RATS_TLS_CONF_FLAGS_SERVER = 1 << 0
RATS_TLS_CONF_FLAGS_MUTUAL = 1 << 1
RATS_TLS_CONF_FLAGS_PROVIDE_ENDORSEMENTS = 1 << 2
RATS_TLS_CERT_ALGO_DEFAULT = 0

# Define RATS-TLS function signatures
lib.rats_tls_init.argtypes = [ctypes.POINTER(RatsTlsConf), ctypes.POINTER(ctypes.POINTER(RatsTlsHandle))]
lib.rats_tls_init.restype = ctypes.c_uint32
lib.rats_tls_negotiate.argtypes = [ctypes.POINTER(RatsTlsHandle), ctypes.c_int]
lib.rats_tls_negotiate.restype = ctypes.c_uint32
lib.rats_tls_transmit.argtypes = [ctypes.POINTER(RatsTlsHandle), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
lib.rats_tls_transmit.restype = ctypes.c_uint32
lib.rats_tls_receive.argtypes = [ctypes.POINTER(RatsTlsHandle), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
lib.rats_tls_receive.restype = ctypes.c_uint32
lib.rats_tls_cleanup.argtypes = [ctypes.POINTER(RatsTlsHandle)]
lib.rats_tls_cleanup.restype = ctypes.c_uint32
lib.rats_tls_set_verification_callback.argtypes = [ctypes.POINTER(RatsTlsHandle), ctypes.c_void_p]
lib.rats_tls_set_verification_callback.restype = ctypes.c_uint32

def _create_socket(ip: str, port: int) -> socket.socket:
    """Create and bind a TCP socket with platform-safe keepalive options."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if sys.platform.startswith("linux"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except AttributeError:
            logger.warning("Keepalive options not available.")
    try:
        sock.bind((ip, port))
        sock.listen(5)
    except socket.error as e:
        sock.close()
        raise RatsTlsError(f"Failed to create socket: {e}")
    return sock

def _configure_rats_tls(
    attester_type: str,
    verifier_type: str,
    tls_type: str,
    crypto_type: str,
    mutual_attestation: bool,
    provide_endorsements: bool,
    log_level: str = "debug"
) -> tuple[RatsTlsConf, list, list]:
    """Create RATS-TLS config and claims. Returns config, claims, and value buffers."""
    log_level_map = {
        "debug": RATS_TLS_LOG_LEVEL_DEBUG,
        "info": RATS_TLS_LOG_LEVEL_INFO,
        "warn": 4,
        "error": 5,
        "fatal": 6,
        "off": 7
    }
    log_level_value = log_level_map.get(log_level.lower(), RATS_TLS_LOG_LEVEL_DEBUG)

    # Create C-compatible buffers for claim values
    value_buffers = [
        ctypes.create_string_buffer(b"value_0"),
        ctypes.create_string_buffer(b"value_1")
    ]

    claims = (Claim * 2)()
    claims[0].name = b"key_0"
    claims[0].value = ctypes.cast(value_buffers[0], ctypes.c_void_p)
    claims[0].value_size = len(b"value_0")
    claims[1].name = b"key_1"
    claims[1].value = ctypes.cast(value_buffers[1], ctypes.c_void_p)
    claims[1].value_size = len(b"value_1")

    conf = RatsTlsConf()
    conf.log_level = log_level_value
    conf.attester_type = attester_type.encode("utf-8")
    conf.verifier_type = verifier_type.encode("utf-8")
    conf.tls_type = tls_type.encode("utf-8")
    conf.crypto_type = crypto_type.encode("utf-8")
    conf.flags = RATS_TLS_CONF_FLAGS_SERVER
    if mutual_attestation:
        conf.flags |= RATS_TLS_CONF_FLAGS_MUTUAL
    if provide_endorsements:
        conf.flags |= RATS_TLS_CONF_FLAGS_PROVIDE_ENDORSEMENTS
    conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT
    conf.custom_claims = ctypes.cast(claims, ctypes.c_void_p)
    conf.custom_claims_length = 2
    return conf, claims, value_buffers

def _handle_client(handle: ctypes.POINTER(RatsTlsHandle), client_sock: socket.socket) -> tuple[str, bytes]:
    """Handle a client connection."""
    conn_fd = client_sock.fileno()
    try:
        result = lib.rats_tls_negotiate(handle, conn_fd)
        if result != RATS_TLS_ERR_NONE:
            raise RatsTlsError(f"Failed to negotiate TLS: error {result}")

        buffer = ctypes.create_string_buffer(256)  # Note: Fixed size, may truncate
        size = ctypes.c_size_t(256)
        result = lib.rats_tls_receive(handle, buffer, ctypes.byref(size))
        if result != RATS_TLS_ERR_NONE:
            raise RatsTlsError(f"Failed to receive message: error {result}")
        if size.value == 256:
            logger.warning("Received message may be truncated due to 256-byte buffer limit")
        received_message = buffer.raw[:size.value].decode("utf-8")

        response = b"Server response: OK"
        size = ctypes.c_size_t(len(response))
        result = lib.rats_tls_transmit(handle, response, ctypes.byref(size))
        if result != RATS_TLS_ERR_NONE:
            raise RatsTlsError(f"Failed to transmit message: error {result}")

        return received_message, response
    finally:
        client_sock.close()  # Close socket here instead of os.close(fd)

def start_server(
    ip: str = "127.0.0.1",
    port: int = 1234,
    attester_type: str = "sev_snp",
    verifier_type: str = "sev_snp",
    tls_type: str = "openssl",
    crypto_type: str = "openssl",
    mutual_attestation: bool = False,
    provide_endorsements: bool = False,
    log_level: str = "debug"
) -> tuple[ctypes.POINTER(RatsTlsHandle), list, list]:
    """Start a RATS-TLS server. Returns handle, claims, and value buffers."""
    conf, claims, value_buffers = _configure_rats_tls(
        attester_type, verifier_type, tls_type, crypto_type, mutual_attestation, provide_endorsements, log_level
    )
    handle = ctypes.POINTER(RatsTlsHandle)()
    result = lib.rats_tls_init(ctypes.byref(conf), ctypes.byref(handle))
    if result != RATS_TLS_ERR_NONE:
        raise RatsTlsError(f"Failed to initialize RATS-TLS: error {result}")

    result = lib.rats_tls_set_verification_callback(handle, None)
    if result != RATS_TLS_ERR_NONE:
        raise RatsTlsError(f"Failed to set verification callback: error {result}")

    server_sock = _create_socket(ip, port)
    print(f"RATS-TLS server listening on {ip}:{port}")

    def server_loop():
        try:
            while True:
                client_sock, addr = server_sock.accept()
                print(f"Accepted connection from {addr}")
                try:
                    received, sent = _handle_client(handle, client_sock)
                    print(f"Received: {received}, Sent: {sent.decode('utf-8')}")
                except Exception as e:
                    logger.error(f"Error handling client {addr}: {e}")
        except KeyboardInterrupt:
            print("Shutting down server...")
        finally:
            server_sock.close()
            lib.rats_tls_cleanup(handle)

    threading.Thread(target=server_loop, daemon=True).start()
    return handle, claims, value_buffers

def connect_client(
    ip: str = "127.0.0.1",
    port: int = 1234,
    attester_type: str = "sev_snp",
    verifier_type: str = "sev_snp",
    tls_type: str = "openssl",
    crypto_type: str = "openssl",
    mutual_attestation: bool = False,
    log_level: str = "debug"
) -> tuple[ctypes.POINTER(RatsTlsHandle), list, list]:
    """Connect to a RATS-TLS server. Returns handle, claims, and value buffers."""
    conf, claims, value_buffers = _configure_rats_tls(
        attester_type, verifier_type, tls_type, crypto_type, mutual_attestation, False, log_level
    )
    conf.flags = 0  # Client mode
    if mutual_attestation:
        conf.flags |= RATS_TLS_CONF_FLAGS_MUTUAL
    handle = ctypes.POINTER(RatsTlsHandle)()
    result = lib.rats_tls_init(ctypes.byref(conf), ctypes.byref(handle))
    if result != RATS_TLS_ERR_NONE:
        raise RatsTlsError(f"Failed to initialize RATS-TLS: error {result}")

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_sock.connect((ip, port))
        conn_fd = client_sock.fileno()
        result = lib.rats_tls_negotiate(handle, conn_fd)
        if result != RATS_TLS_ERR_NONE:
            raise RatsTlsError(f"Failed to negotiate TLS: error {result}")
    except (socket.error, RatsTlsError) as e:
        client_sock.close()
        lib.rats_tls_cleanup(handle)
        raise RatsTlsError(f"Client connection failed: {e}")

    return handle, claims, value_buffers

def send_message(handle: ctypes.POINTER(RatsTlsHandle), message: str) -> None:
    """Send a message over RATS-TLS."""
    message_bytes = message.encode("utf-8")
    size = ctypes.c_size_t(len(message_bytes))
    result = lib.rats_tls_transmit(handle, message_bytes, ctypes.byref(size))
    if result != RATS_TLS_ERR_NONE:
        raise RatsTlsError(f"Failed to send message: error {result}")

def receive_message(handle: ctypes.POINTER(RatsTlsHandle)) -> str:
    """Receive a message over RATS-TLS."""
    buffer = ctypes.create_string_buffer(256)  # Note: Fixed size, may truncate
    size = ctypes.c_size_t(256)
    result = lib.rats_tls_receive(handle, buffer, ctypes.byref(size))
    if result != RATS_TLS_ERR_NONE:
        raise RatsTlsError(f"Failed to receive message: error {result}")
    if size.value == 256:
        logger.warning("Received message may be truncated due to 256-byte buffer limit")
    return buffer.raw[:size.value].decode("utf-8")

def close_connection(handle: ctypes.POINTER(RatsTlsHandle)) -> None:
    """Close a RATS-TLS connection safely, idempotent."""
    if handle and handle.contents:  # Check if handle is valid and not cleared
        result = lib.rats_tls_cleanup(handle)
        if result != RATS_TLS_ERR_NONE:
            raise RatsTlsError(f"Failed to close connection: error {result}")
        handle.contents = None  # Clear handle to prevent double cleanup

if __name__ == "__main__":
    server_handle, server_claims, server_value_buffers = start_server(
        mutual_attestation=True,
        provide_endorsements=True
    )
    client_handle, client_claims, client_value_buffers = connect_client(
        mutual_attestation=True
    )
    send_message(client_handle, "Hello, RATS-TLS!")
    response = receive_message(client_handle)
    print(f"Client received: {response}")
    close_connection(client_handle)
    # Server runs in background; use Ctrl+C to stop