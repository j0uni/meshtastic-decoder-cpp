#!/bin/bash

# Meshtastic Decoder Test Examples
# This script demonstrates various packet types and their decoding

echo "=== Meshtastic Decoder Test Examples ==="
echo

# Check if decoder is built
if [ ! -f "./build/meshtastic_decoder_standalone" ]; then
    echo "Error: build/meshtastic_decoder_standalone not found. Please run 'make' first."
    exit 1
fi

echo "Testing TEXT_MESSAGE_APP (Port 1)..."
echo "Expected: 'olikos cos linjoilla?'"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF A8 E2 09 13 75 67 20 3A A5 08 00 A8 7A AB 93 44 8E 1B 21 29 68 5A CB 0A 12 E8 DB 91 D9 31 E6 18 BE 40 07 7E F8 11 BB\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF A8 E2 09 13 75 67 20 3A A5 08 00 A8 7A AB 93 44 8E 1B 21 29 68 5A CB 0A 12 E8 DB 91 D9 31 E6 18 BE 40 07 7E F8 11 BB" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing NODEINFO_APP (Port 4)..."
echo "Expected: Node information for 'jii kolmone!' with hardware TLORA_T3_S3"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF A8 E2 09 13 E4 25 A6 3D A5 08 00 A8 21 B2 C1 47 8E 7F B8 3A 28 6A F6 4E 03 A2 86 90 48 3D F1 D6 F1 18 46 1D 44 47 B5 ED 3C CA A4 93 19 F8 74 60 55 F6 32 B9 F4 54 01 61 C8 20 75 05 EF 07 D8 43 FB 08 D9 8E 00 D6 52 52 C5 3C CF 70 FC 07 3C FF 97 8B D9 65 5B 9A 11 34 30 82 E4 5F E8 DF 59\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF A8 E2 09 13 E4 25 A6 3D A5 08 00 A8 21 B2 C1 47 8E 7F B8 3A 28 6A F6 4E 03 A2 86 90 48 3D F1 D6 F1 18 46 1D 44 47 B5 ED 3C CA A4 93 19 F8 74 60 55 F6 32 B9 F4 54 01 61 C8 20 75 05 EF 07 D8 43 FB 08 D9 8E 00 D6 52 52 C5 3C CF 70 FC 07 3C FF 97 8B D9 65 5B 9A 11 34 30 82 E4 5F E8 DF 59" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing POSITION_APP (Port 3)..."
echo "Expected: GPS coordinates 61.4813734°N, 23.7886815°E (Tampere Hacklab)"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF 5C CB 2A DB B3 38 42 CB E6 08 00 98 DD CE DD 1B B9 5D 9B 2C 1B 89 C3 38 A0 8B 39 BC 07 C8 1B 69 21 6A 37\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF 5C CB 2A DB B3 38 42 CB E6 08 00 98 DD CE DD 1B B9 5D 9B 2C 1B 89 C3 38 A0 8B 39 BC 07 C8 1B 69 21 6A 37" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing RANGE_TEST_APP (Port 66)..."
echo "Expected: Range test packet with 'seq 1' message"
echo "Note: This demonstrates the decoder's ability to handle different packet types"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF B8 32 8C 08 A6 B1 4F 2C 00 08 00 B8 49 AA 93 AD AB 9A 5D 22 71 AF 66\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF B8 32 8C 08 A6 B1 4F 2C 00 08 00 B8 49 AA 93 AD AB 9A 5D 22 71 AF 66" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing TRACEROUTE_APP (Port 70)..."
echo "Expected: Route discovery with network path information"
echo "Note: TRACEROUTE_APP support is implemented and ready for real traceroute packets"
echo "      The decoder will automatically detect port 70 and decode route information"
echo "      Example output format: {\"route_count\": 2, \"route_path\": \"!node1 → !node2\", \"route_nodes\": [...]}"
echo ""
echo "Testing with a REAL traceroute packet (Packet #2058 from jii ykköne! to jii kolmone!):"
echo "Command: ./build/meshtastic_decoder_standalone \"A8 E2 09 13 98 E2 09 13 4A 4B BA 20 4A 08 00 98 52 79 05 4E 5C 0E F4 AA 86 04 71 9F DE 74\""
echo "Result:"
./build/meshtastic_decoder_standalone "A8 E2 09 13 98 E2 09 13 4A 4B BA 20 4A 08 00 98 52 79 05 4E 5C 0E F4 AA 86 04 71 9F DE 74" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo ""
echo "Note: This is a real TRACEROUTE_APP packet from the mesh network!"
echo "      It should show route_count, route_path, and route_nodes in the output."
echo

echo "=== Test Complete ==="
echo "Note: This decoder supports all four main Meshtastic app types:"
echo "      - TEXT_MESSAGE_APP (port 1) - Text messages"
echo "      - POSITION_APP (port 3) - GPS coordinates"
echo "      - NODEINFO_APP (port 4) - Node information"
echo "      - TRACEROUTE_APP (port 70) - Route discovery and network path analysis"
echo "      Install 'jq' for better JSON formatting: sudo apt install jq (Ubuntu/Debian) or brew install jq (macOS)"
