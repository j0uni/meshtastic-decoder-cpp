# Meshtastic Decoder - C++ Standalone Implementation

A pure C++ implementation of a Meshtastic packet decoder with **no external dependencies**. This decoder can decrypt and parse Meshtastic radio packets, extracting text messages, GPS coordinates, and node information.

## Features

- **Pure C++ Implementation** - No external libraries required
- **Barebones AES-128-CTR** - Custom AES implementation for decryption
- **Packet Decoding** - Supports TEXT_MESSAGE_APP, POSITION_APP, NODEINFO_APP, and TRACEROUTE_APP
- **GPS Coordinates** - Extracts latitude, longitude, and altitude
- **Text Messages** - Decodes text messages from the mesh network
- **Node Information** - Parses node IDs, names, and hardware details
- **Route Discovery** - Decodes network path information from traceroute packets
- **JSON Output** - Clean JSON format for easy integration

## Current Status

This decoder currently has **full support** for:
-  **TEXT_MESSAGE_APP** (Port 1) - Text messages with working test examples
-  **POSITION_APP** (Port 3) - GPS coordinates and position data
-  **NODEINFO_APP** (Port 4) - Node information and hardware details
-  **TRACEROUTE_APP** (Port 70) - Route discovery and network path analysis
-  **RANGE_TEST_APP** (Port 66) - Range testing packets

The decoder framework supports all four main message types with complete implementations and working test examples. TRACEROUTE_APP support is fully implemented and ready for real traceroute packets from the mesh network.

**Note**: This is a community-driven project. If you have additional packet examples or encounter any issues, please contribute them to improve the test coverage.

## Quick Start

### Prerequisites

- C++11 compatible compiler (g++, clang++, etc.)
- Make

### Compilation

```bash
git clone https://github.com/j0uni/meshtastic-decoder-cpp.git
cd meshtastic-decoder-cpp
make
```

The build system uses strict compiler flags (`-Werror -Wfatal-errors`).

### Usage

```bash
./build/meshtastic_decoder_standalone "FF FF FF FF A8 E2 09 13 75 67 20 3A A5 08 00 A8 7A AB 93 44 8E 1B 21 29 68 5A CB 0A 12 E8 DB 91 D9 31 E6 18 BE 40 07 7E F8 11 BB"
```

### Example Output

**Text Message:**
```json
{
  "success": true,
  "header": {
    "to_address": "0xffffffff",
    "from_address": "0x1309e2a8",
    "packet_id": "0x3a206775",
    "flags": "0xa5",
    "channel": 8,
    "next_hop": 0,
    "relay_node": 168
  },
  "port": 1,
  "app_name": "TEXT_MESSAGE_APP",
  "text_message": "olikos cos linjoilla?"
}
```

**Traceroute (Route Discovery):**
```json
{
  "success": true,
  "port": 70,
  "app_name": "TRACEROUTE_APP",
  "traceroute": {
    "route_count": 2,
    "route_path": "!00000001 → !00000002",
    "route_nodes": ["0x00000001", "0x00000002"]
  }
}
```

## Building from Source

### Dependencies
- C++11 compatible compiler
- Make

### Compilation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/j0uni/meshtastic-decoder-cpp.git
   cd meshtastic-decoder-cpp
   ```

2. **Build the decoder:**
   ```bash
   make
   ```

3. **Test the build:**
   ```bash
   ./build/meshtastic_decoder_standalone "FF FF FF FF A8 E2 09 13 75 67 20 3A A5 08 00 A8 7A AB 93 44 8E 1B 21 29 68 5A CB 0A 12 E8 DB 91 D9 31 E6 18 BE 40 07 7E F8 11 BB"
   ```

### Makefile Targets

- `make` or `make all` - Build the decoder
- `make clean` - Remove build artifacts
- `make test` - Run basic functionality tests
- `make test-text` - Test text message decoding
- `make test-position` - Test position decoding
- `make help` - Show all available targets

### Build System Features

- **Strict Compilation**: Uses `-Werror -Wfatal-errors` to treat warnings as errors
- **Organized Structure**: Builds into `build/` directory
- **Clean Separation**: Source files remain in root, objects in build directory
- **Zero Warnings**: All compiler warnings are fixed

## Testing

### Automated Testing

Run the comprehensive test suite:

```bash
./test_examples.sh
```

This script tests all supported packet types and provides expected outputs.

## Architecture

### Core Components

1. **AES128Barebones** (`aes_barebones.cpp/h`)
   - Pure C++ AES-128 implementation
   - CTR mode with big-endian counter increment
   - No external dependencies

2. **MeshtasticDecoderStandalone** (`meshtastic_decoder_standalone.cpp`)
   - Main decoder class
   - Packet header parsing
   - Protobuf decoding
   - JSON output generation

### Key Features

- **Zero Dependencies**: No external libraries required
- **Cross-Platform**: Works on Linux, macOS, Windows
- **Memory Safe**: Proper bounds checking and error handling
- **Efficient**: Optimized for embedded systems
- **Clean Code**: Zero compiler warnings with strict flags

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Meshtastic](https://meshtastic.org/) - The amazing mesh networking project

