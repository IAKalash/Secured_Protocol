# SecuredProtocol

## Overview

`SecuredProtocol` is a secure messaging protocol implementation that ensures confidentiality, integrity, and authenticity of messages exchanged between two parties. The project uses modern cryptographic techniques including ECDH for key exchange, AES-256-GCM for encryption, HKDF for key derivation, and ECDSA for message signing. It supports both IPv4 and IPv6 communication over TCP sockets.

This project was developed as part of a coursework to demonstrate secure communication using the OpenSSL library. It includes a client-server architecture where two parties can exchange encrypted and signed messages in real-time.

## Features

- **Key Exchange**: Uses ECDH (Elliptic Curve Diffie-Hellman) on the secp256k1 curve to establish a shared secret.
- **Key Derivation**: Derives encryption keys using HKDF with SHA-256 and a fixed salt (`protocol salt`).
- **Encryption**: Encrypts messages with AES-256-GCM, including a 12-byte IV and a 16-byte authentication tag.
- **Message Signing**: Signs messages with ECDSA (secp256k1 curve) to ensure authenticity.
- **Network Communication**: Implements a TCP-based client-server model with support for IPv4 and IPv6.
- **Cross-Platform**: Works on both Linux and Windows with minimal setup.

## Project Structure

```
SecuredProtocol/
├── .vscode/                  # VSCode configuration files (optional)
├── build/                    # Build directory (generated)
├── include/                  # Header files
│   ├── applink.h             # OpenSSL applink for Windows compatibility
│   ├── crypto_functions.h    # Cryptographic function declarations
│   └── net_sockets.h         # Networking function declarations
├── src/                      # Source files
│   ├── crypto_functions.c    # Cryptographic function implementations
│   ├── main.c                # Main application logic
│   └── net_sockets.c         # Networking function implementations
├── CMakeLists.txt            # CMake build configuration
└── README.md                 # Project documentation (this file)
```

### File Descriptions

- **`applink.h`**: Provides OpenSSL compatibility for Windows by defining I/O functions.
- **`crypto_functions.h` / `crypto_functions.c`**: Implements cryptographic operations (ECDH, HKDF, AES-256-GCM, ECDSA).
- **`net_sockets.h` / `net_sockets.c`**: Handles TCP socket communication for both client and server, including message serialization.
- **`main.c`**: Entry point of the application, orchestrates key exchange, message encryption/decryption, and communication.
- **`CMakeLists.txt`**: CMake configuration for building the project with OpenSSL dependencies.

## Prerequisites

Before compiling and running the project, ensure you have the following installed:

### General Requirements
- **CMake**: Version 3.10 or higher.
- **OpenSSL**: Required for cryptographic operations.
- **C Compiler**: GCC (Linux) or MinGW (Windows).
- **Git**: To clone the repository.

### Linux
- Install dependencies on a Debian-based system (e.g., Ubuntu):
  ```bash
  sudo apt update
  sudo apt install build-essential cmake libssl-dev
  ```

### Windows
- Install MSYS2 (provides MinGW and OpenSSL):
  1. Download and install MSYS2 from [https://www.msys2.org/](https://www.msys2.org/).
  2. Open the MSYS2 MinGW 64-bit terminal and install dependencies:
     ```bash
     pacman -Syu
     pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl
     ```
- Ensure the MinGW `gcc` is in your PATH (e.g., `C:\msys64\mingw64\bin`).

## Building the Project

### Clone the Repository
```bash
git clone https://github.com/<your-username>/SecuredProtocol.git
cd SecuredProtocol
```

### Linux
1. Create a build directory:
   ```bash
   mkdir build && cd build
   ```
2. Configure the project with CMake:
   ```bash
   cmake -S .. -B .
   ```
3. Build the project:
   ```bash
   cmake --build .
   ```
   (You can also use CTRL + SHIFT + B)

### Windows (Using MSYS2)
1. Open the MSYS2 MinGW 64-bit terminal.
2. Navigate to the project directory:
   ```bash
   cd /path/to/SecuredProtocol
   ```
3. Create a build directory:
   ```bash
   mkdir build && cd build
   ```
4. Configure the project with CMake:
   ```bash
   cmake -S .. -B . -G "MinGW Makefiles" -DCMAKE_C_COMPILER=C:/msys64/mingw64/bin/gcc.exe
   ```
5. Build the project:
   ```bash
   cmake --build .
   ```
   (You can also use CTRL + SHIFT + B)

The executable will be located in `build/bin/SecuredProtocol` (Linux) or `build/bin/SecuredProtocol.exe` (Windows).

## Running the Project

### General Usage
The application can run in two modes: server or client. The server listens for incoming connections, while the client connects to the server to exchange messages.

- **Server Mode**:
  ```bash
  ./build/bin/SecuredProtocol --server <port>
  ```
- **Client Mode**:
  ```bash
  ./build/bin/SecuredProtocol --client <hostname-or-ip> <port>
  ```

### Example
1. Start the server on port 2300 in one terminal:
   ```bash
   ./build/bin/SecuredProtocol --server 2300
   ```
   Output:
   ```
   ---
   server: waiting for connections...
   ```
2. Start the client in another terminal, connecting to the server (e.g., `::1` for localhost IPv6):
   ```bash
   ./build/bin/SecuredProtocol --client ::1 2300
   ```
   Output:
   ```
   ---
   Client: Connecting to server...

   client: successfully connected to ::1
   Conversation key: <key>
   Print /close to stop the conversation
   ---
   ```
3. Exchange messages:
   - Type a message in either terminal and press Enter to send.
   - The other side will display the message immediately as `Mate> <message>`.
   - Type `/close` to end the conversation on both sides.

### Notes
- Use ports above 1024 (e.g., 2300) to avoid permission issues.
- For IPv4, use `127.0.0.1` instead of `::1`.
- On Windows, run the commands in the MSYS2 MinGW 64-bit terminal or add `build/bin` to your PATH and run in CMD/PowerShell:
  ```cmd
  build\bin\SecuredProtocol.exe --server 2300
  ```

## Troubleshooting

- **OpenSSL Not Found**: Ensure OpenSSL is installed and the paths in `CMakeLists.txt` match your system (e.g., update `OPENSSL_ROOT_DIR` for Windows).
- **Connection Issues**: Verify the port is not blocked by a firewall and the IP address is correct.
- **Windows Input Issues**: If input doesn't display, run in CMD instead of PowerShell.

## Technical Details

### Cryptographic Implementation
- **ECDH**: Uses the secp256k1 curve for key exchange (RFC 7748).
- **HKDF**: Derives a 32-byte encryption key with SHA-256 and a fixed salt (`protocol salt`) (RFC 5869).
- **AES-256-GCM**: Encrypts messages with a 12-byte IV and 16-byte tag (NIST SP 800-38D).
- **ECDSA**: Signs messages for authenticity (FIPS 186-4).
- **OpenSSL**: Leverages OpenSSL for all cryptographic operations.

### Network Implementation
- **TCP Sockets**: Uses POSIX sockets on Linux and Winsock on Windows.
- **Message Format**: Messages include IV (12 bytes), tag (16 bytes), ciphertext length (4 bytes), ciphertext, signature length (4 bytes), and signature.
- **Real-Time Messaging**: Messages are delivered instantly using `poll` (Linux) or `WSAPoll` (Windows).

## Acknowledgments
- Built using the [OpenSSL](https://www.openssl.org/) library.
- Inspired by [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/).
- References: RFC 7748, RFC 5869, NIST SP 800-38D, FIPS 186-4.