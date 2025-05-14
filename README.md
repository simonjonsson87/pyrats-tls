# pyrats_tls

`pyrats_tls` is a Python package providing bindings for [RATS-TLS](https://github.com/inclavare-containers/rats-tls), enabling secure communication with remote attestation over TLS. It supports server and client modes, with features like mutual attestation and SEV-SNP attestation on Linux. The package is built using `cffi` and integrates a native wrapper (`rats_tls_wrapper`) for the RATS-TLS C library.

## Features

- Start RATS-TLS servers and clients with customizable attestation types (e.g., SEV-SNP, nullattester).
- Support for mutual attestation and custom attestation tokens.
- Secure message passing over TLS with attestation verification.
- Platform-specific support, with full functionality on Linux and limited support on macOS/Windows.
- Built with CMake for native library integration and tested with `pytest`.

## Requirements

- **Python**: >=3.7
- **Operating System**: Linux for full functionality (SEV-SNP requires specific hardware); partial support on macOS and Windows.
- **Dependencies**: `cffi`, `rats-tls` library, and build tools (CMake, Ninja, OpenSSL, libcbor).

## Installation

Once wheels are available, install `pyrats_tls` using `pip`:

```bash
pip install pyrats_tls

For now, build from source (see Development Setup below) due to ongoing wheel generation.
Note: Full functionality requires a Linux system with rats-tls installed. On macOS/Windows, only client mode with limited attestation is supported.
Usage
Below are examples of using pyrats_tls to set up a server and client, adapted from the test suite.
Starting a Server
Start a RATS-TLS server without mutual attestation:
from pyrats_tls import start_server, verify_attestation_token, close_connection

# Start server on localhost:4444
token, connection = start_server(
    ip="127.0.0.1",
    port=4444,
    mutual_attestation=False,
    attester_type="nullattester",
    verifier_type="nullverifier"
)

# Verify attestation token
assert verify_attestation_token(token)
print(f"Server started with token: {token}")

# Keep server running (handled by a background thread)
# Close when done
close_connection(connection)

Connecting a Client
Connect a client to the server with mutual attestation:
from pyrats_tls import connect_ra_tls_client, send_message, receive_message, verify_attestation_token, close_connection

# Connect to server
token, connection = connect_ra_tls_client(
    ip="127.0.0.1",
    port=4444,
    mutual_attestation=True,
    attester_type="sev_snp",
    verifier_type="sev_snp"
)

# Verify attestation token
assert verify_attestation_token(token)
print(f"Client connected with token: {token}")

# Send and receive a message
send_message(connection, "Hello, RATS-TLS!")
response = receive_message(connection)
print(f"Received: {response}")

# Close connection
close_connection(connection)

Message Passing
Test server-client communication:
import threading
import time
from pyrats_tls import start_server, connect_ra_tls_client, send_message, receive_message, close_connection

def server_thread():
    token, conn = start_server("127.0.0.1", 4445, mutual_attestation=False)
    message = receive_message(conn)
    print(f"Server received: {message}")
    close_connection(conn)

def client_thread():
    time.sleep(0.1)  # Ensure server starts
    token, conn = connect_ra_tls_client("127.0.0.1", 4445, mutual_attestation=False)
    send_message(conn, "Hello, RATS-TLS!")
    close_connection(conn)

server_t = threading.Thread(target=server_thread)
client_t = threading.Thread(target=client_thread)
server_t.start()
client_t.start()
server_t.join(timeout=5)
client_t.join(timeout=5)

Development Setup
To build pyrats_tls from source:

Clone the Repository:
git clone https://github.com/simonjonsson87/pyrats_tls.git
cd pyrats_tls


Install Dependencies:
On Ubuntu:
sudo apt-get update
sudo apt-get install -y git make autoconf libtool gcc g++ libssl-dev libcbor-dev
pip install setuptools wheel cffi cmake ninja


Build rats-tls:
git clone https://github.com/inclavare-containers/rats-tls.git
cd rats-tls
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local -DTLS_TYPE=openssl -DWITH_SGX=OFF -DWITH_SEV=ON
sudo cmake --build build --target install
cd ..


Build Wheels:
pip install cibuildwheel
cibuildwheel --platform linux --output-dir wheelhouse


Install Locally:
pip install wheelhouse/pyrats_tls-0.1.0-*.whl



Note: Ensure pyproject.toml uses package-dir = {"pyrats_tls": "pyrats_tls"} to avoid build errors.
Testing
Run the test suite using pytest:
pip install pytest
pytest tests -v

The tests cover:

Server startup with/without mutual attestation (test_server.py).
Client connections and message passing (test_client.py).
Native library loading and edge cases (test_load_native.py).

Note: Some tests require Linux and may skip on macOS/Windows or if SEV-SNP hardware is unavailable.
Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a pull request.

Please include tests and update documentation. Report issues at GitHub Issues.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgments

Built on RATS-TLS by Inclavare Containers.
Inspired by the need for secure, attested communication in Python applications.



