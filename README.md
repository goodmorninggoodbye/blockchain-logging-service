# Blockchain-Based Secure Logging Infrastructure

Tamper-evident logging system with cryptographic proof-of-work and hash-chained integrity verification.
Built in C with SHA-256 blockchain principles

## Key Features

- **Cryptographic Proof-of-Work**: SHA-256 mining with 20 leading zero bits prevents denial-of-service attacks and spam
- **Hash-Chained Integrity**: Each log entry cryptographically links to previous entries, enabling tamper detection
- **Distributed Architecture**: Client-server design supporting remote log submission and centralized verification
- **Comprehensive Validation**: Full blockchain traversal verification with automated integrity checking
- **Secure Timestamping**: Immutable timestamp records with cryptographic binding to log content
- **Base64 Hash Encoding**: Efficient storage and transmission of cryptographic hash chains

## Architecture Overview

### Core Components

**Log Client (`log`)**
- Generates cryptographic proof-of-work for message authentication
- Implements SHA-256 mining algorithm with configurable difficulty
- Secure network communication with automatic connection handling

**Blockchain Server (`logserver`)**
- Maintains tamper-evident log chain with hash linking
- Validates proof-of-work submissions and prevents replay attacks
- Atomic log operations with persistent storage and head pointer management

**Integrity Validator (`checklog`)**
- Traverses entire blockchain to verify cryptographic integrity
- Detects any modification, deletion, or corruption in log history
- Validates hash chain continuity and proof-of-work compliance

**Hash Utility (`b64hash`)**
- Standalone SHA-256 hash computation with Base64 encoding
- Testing and debugging tool for cryptographic operations

### Blockchain Design

```
Genesis Entry ──→ Entry 1 ──→ Entry 2 ──→ ... ──→ Latest Entry
    │               │           │                      │
   "start"      hash(prev)   hash(prev)           hash(prev)
                     ↓           ↓                      ↓
                  Hash Chain Verification         Head Pointer
```

- **Immutable Linking**: Each entry contains cryptographic hash of previous entry
- **Tamper Detection**: Any modification breaks hash chain and is immediately detectable
- **Proof-of-Work**: 20-bit difficulty prevents unauthorized log injection
- **Head Tracking**: Secure pointer management for efficient blockchain growth

## Technical Specifications

- **Language**: C (C99 standard)
- **Cryptography**: SHA-256 hashing algorithm with custom proof-of-work
- **Networking**: TCP/IPv4 client-server communication
- **Encoding**: Base64 for hash representation and storage
- **Build System**: GNU Make with optimized compilation flags
- **Storage**: Persistent file-based blockchain with atomic operations
- **Validation**: Complete blockchain integrity verification

## Security Features

- **Anti-DoS Protection**: Proof-of-work requirement (20 leading zero bits) prevents spam attacks
- **Tamper Evidence**: Cryptographic hash chaining detects any unauthorized modifications
- **Integrity Verification**: Complete blockchain validation with automatic corruption detection
- **Secure Communication**: Client-server protocol with message validation and error handling
- **Atomic Operations**: Thread-safe log operations with consistent state management

## Performance Characteristics

- **Proof-of-Work Generation**: Variable time based on hash difficulty (typically 1-30 seconds)
- **Log Verification**: O(n) complexity for complete blockchain validation
- **Storage Efficiency**: Minimal overhead with compressed Base64 hash representation
- **Network Latency**: Sub-second response times for log submission
- **Scalability**: Linear growth with blockchain length, optimized for audit trail use cases

## Build & Deployment

### Prerequisites
```bash
# Required: GCC with C99 support
gcc --version  # Verify GCC installation
```

### Compilation
```bash
make           # Builds all components: log, logserver, checklog, b64hash
make clean     # Clean build artifacts
```

### Deployment
```bash
# Start blockchain server (assigns random port)
./logserver

# Submit log entry with proof-of-work
./log <port> "Secure log message"

# Verify complete blockchain integrity
./checklog

# Generate standalone hash for testing
./b64hash "test message"
```

## Protocol Specification

### Client-Server Communication
```
Client                    Server
  │                         │
  ├── Proof-of-Work ────────→│
  │   Generation             │── Validates PoW
  │                         │── Links to chain
  │                         │── Updates head
  │←──── "ok" response ──────┤
```

### Message Format
```
<8-digit-hex-pow>:<log-message>
```

### Log Entry Structure
```
YYYY-MM-DD HH:MM:SS - <previous-hash> <message-content>
```

### Hash Chain Verification
- **Genesis Entry**: Contains "start" as previous hash
- **Subsequent Entries**: Contain 24-character Base64 hash of previous entry
- **Head Pointer**: Stored in `loghead.txt` for efficient chain growth
- **Validation**: Complete traversal ensures unbroken cryptographic chain

## Implementation Highlights

- **Cryptographic Security**: Industry-standard SHA-256 with proof-of-work consensus mechanism
- **Fault Tolerance**: Robust error handling for network failures and corrupted data
- **Memory Safety**: Comprehensive bounds checking and resource cleanup
- **Modular Design**: Separate concerns for hashing, networking, and blockchain logic
- **Standards Compliance**: POSIX-compatible networking and file operations

## Use Cases

### Security Monitoring
- **Audit Trails**: Tamper-evident logs for compliance and forensic analysis
- **Intrusion Detection**: Immutable security event logging with cryptographic integrity
- **Compliance Reporting**: Verifiable log chains for regulatory requirements

### Financial Systems
- **Transaction Logging**: Immutable financial transaction records
- **Regulatory Compliance**: Tamper-evident audit trails for financial institutions
- **Fraud Detection**: Cryptographically secured transaction history

### Healthcare & Government
- **HIPAA Compliance**: Secure medical record access logging
- **Government Auditing**: Tamper-evident government operation logs
- **Legal Evidence**: Cryptographically verifiable digital evidence chains

## Code Quality Features

- **Memory Management**: Comprehensive malloc/free pairing with leak detection
- **Error Handling**: Detailed error messages and graceful failure modes
- **Input Validation**: Robust parsing with bounds checking and format validation
- **Documentation**: Inline comments explaining cryptographic operations
- **Testing**: Verification utilities for end-to-end blockchain validation

## Scalability Considerations

### Current Implementation
- File-based persistent storage with atomic operations
- Single-threaded server with sequential log processing
- In-memory validation for complete blockchain verification

### Production Enhancements
- **Database Integration**: PostgreSQL/MongoDB for enterprise-scale storage
- **Horizontal Scaling**: Multi-node blockchain with consensus protocols
- **Performance Optimization**: Parallel verification and incremental validation
- **Monitoring**: Prometheus metrics for blockchain health and performance

## Getting Started

1. **Clone and build**:
   ```bash
   git clone <repository>
   cd blockchain-logging-service
   make
   ```

2. **Start the blockchain server**:
   ```bash
   ./logserver
   # Note the assigned port number
   ```

3. **Submit secure log entries**:
   ```bash
   # Replace 12345 with actual server port
   ./log 12345 "Critical security event detected"
   ./log 12345 "User authentication successful"
   ```

4. **Verify blockchain integrity**:
   ```bash
   ./checklog
   # Outputs "valid" if blockchain is intact
   ```

## Contributing
Demonstrates production-ready patterns for:
- Blockchain and distributed ledger implementation
- Cryptographic proof-of-work systems
- Tamper-evident audit trail design
- Secure client-server protocols in C
