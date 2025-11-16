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

echo "Testing additional WAYPOINT_APP examples (Port 8)..."
echo "These are real packets from the mesh network showing different routing scenarios:"
echo

echo "Example 1: WAYPOINT_APP with hop_limit=5, skip_count=2 (relayed 2 times)"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF A8 E2 09 13 BC 4B 9F 30 A5 08 00 A8 9E 77 2F C2 06 53 1A BC 24 B6 95 47 1E 1F D2 CD 31 5C F1 A5 72 99 3D DB 15 20 41 B5 2A F2 AD 92 03 FF BF F8\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF A8 E2 09 13 BC 4B 9F 30 A5 08 00 A8 9E 77 2F C2 06 53 1A BC 24 B6 95 47 1E 1F D2 CD 31 5C F1 A5 72 99 3D DB 15 20 41 B5 2A F2 AD 92 03 FF BF F8" | jq '.routing' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Example 2: WAYPOINT_APP with hop_limit=0, skip_count=7 (heavily relayed)"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF 24 F3 EC 9E C5 25 B8 87 60 08 00 A8 36 04 8B 99 21 4E E5 4F 61 90 2B 4C BF 9F 4F 0C A2 B8 27 1C C9 10 BE B4 73 D3 32 8F 8D DE 96 0C 71\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF 24 F3 EC 9E C5 25 B8 87 60 08 00 A8 36 04 8B 99 21 4E E5 4F 61 90 2B 4C BF 9F 4F 0C A2 B8 27 1C C9 10 BE B4 73 D3 32 8F 8D DE 96 0C 71" | jq '.routing' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Example 3: WAYPOINT_APP with hop_limit=4, skip_count=3 (moderately relayed)"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF 5C CB 2A DB 9A 79 AE 00 E4 08 00 E8 B6 C9 8C EF 0C 68 2F CA E0 05 43 90 51 E5 9C 36 8F 4A FC 22 C4 91 0A\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF 5C CB 2A DB 9A 79 AE 00 E4 08 00 E8 B6 C9 8C EF 0C 68 2F CA E0 05 43 90 51 E5 9C 36 8F 4A FC 22 C4 91 0A" | jq '.routing' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Example 4: WAYPOINT_APP with different node IDs (from database)"
echo "Command: ./build/meshtastic_decoder_standalone \"00 00 00 00 98 E2 09 13 1E 80 9C F5 00 08 00 98 DA CC 0A 2B 2B 1A 78 5C E4 C5 33 2A 8B D3 22 93 AA 2E D4 C0 E1 91 76 34 E1 E3 0A 2C 96 6A 27 2A 2B\""
echo "Result:"
./build/meshtastic_decoder_standalone "00 00 00 00 98 E2 09 13 1E 80 9C F5 00 08 00 98 DA CC 0A 2B 2B 1A 78 5C E4 C5 33 2A 8B D3 22 93 AA 2E D4 C0 E1 91 76 34 E1 E3 0A 2C 96 6A 27 2A 2B" | jq '.routing' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing TELEMETRY_APP (Port 67)..."
echo "Expected: Device telemetry data with GPS time and device metrics"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF 98 E2 09 13 63 47 1F 74 A5 08 00 98 56 F7 03 F4 CE 26 9A C0 72 BC D0 B4 63 89 27 72 BF AB AE CB 7B A1 38 13 CF A2 62 93 2A 73 52 18 CC\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF 98 E2 09 13 63 47 1F 74 A5 08 00 98 56 F7 03 F4 CE 26 9A C0 72 BC D0 B4 63 89 27 72 BF AB AE CB 7B A1 38 13 CF A2 62 93 2A 73 52 18 CC" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing TELEMETRY_APP (Port 67) - Environment metrics example..."
echo "Expected: Environment telemetry data (temperature, etc.)"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF 00 FB E7 1D F2 54 D2 2A 62 55 00 24 FA 38 3C 25 35 30 C9 9F A0 74 1D 4B 7B E9 92 94 AD 0B 5A 74 51 6B 42 FC 31 3C D9 A3 35 AF 3C AC E9 81\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF 00 FB E7 1D F2 54 D2 2A 62 55 00 24 FA 38 3C 25 35 30 C9 9F A0 74 1D 4B 7B E9 92 94 AD 0B 5A 74 51 6B 42 FC 31 3C D9 A3 35 AF 3C AC E9 81" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing POSITION_APP (Port 3) - Recent GPS data..."
echo "Expected: GPS coordinates 61.4924288°N, 23.8616576°E with altitude 104m"
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF 98 E2 09 13 62 FF 8E DE A5 08 00 98 56 5C B0 21 CD B6 71 28 1B 67 5C 14 6C 31 5D 0D 26 B7 EA 2D CD FA 81 AC 2F 90 06 07 19 E7 AA C9 B0 34 C6 22\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF 98 E2 09 13 62 FF 8E DE A5 08 00 98 56 5C B0 21 CD B6 71 28 1B 67 5C 14 6C 31 5D 0D 26 B7 EA 2D CD FA 81 AC 2F 90 06 07 19 E7 AA C9 B0 34 C6 22" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing POSITION_APP (Port 3) - Additional position test 1..."
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF 08 8D D1 69 9E 7D 4E F8 E0 55 00 24 74 CF 8B 2C 38 90 B0 15 C3 67 29 81 B8 58 03 E1 26 17 20 97 D2 43 D1 12 85 D0 80 C7 9D 07 CF 53 EB EF 60 63 5E 77 BF 14 F9 92\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF 08 8D D1 69 9E 7D 4E F8 E0 55 00 24 74 CF 8B 2C 38 90 B0 15 C3 67 29 81 B8 58 03 E1 26 17 20 97 D2 43 D1 12 85 D0 80 C7 9D 07 CF 53 EB EF 60 63 5E 77 BF 14 F9 92" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "Testing POSITION_APP (Port 3) - Additional position test 2..."
echo "Command: ./build/meshtastic_decoder_standalone \"FF FF FF FF 28 9E 81 EE 79 9C 44 51 C5 55 00 24 49 D7 37 09 C3 8C 23 B9 F0 78 15 D7 39 07 AC 43 DF 11 C3 98 05 17 32 2A BC 52 58 7A B0 7D B2 64 E4 BB 6C 89 0C 6D 3D 11 81 DC\""
echo "Result:"
./build/meshtastic_decoder_standalone "FF FF FF FF 28 9E 81 EE 79 9C 44 51 C5 55 00 24 49 D7 37 09 C3 8C 23 B9 F0 78 15 D7 39 07 AC 43 DF 11 C3 98 05 17 32 2A BC 52 58 7A B0 7D B2 64 E4 BB 6C 89 0C 6D 3D 11 81 DC" | jq '.' 2>/dev/null || echo "jq not available, raw output above"
echo

echo "=== Test Complete ==="
echo "Note: This decoder supports all main Meshtastic app types:"
echo "      - TEXT_MESSAGE_APP (port 1) - Text messages"
echo "      - POSITION_APP (port 3) - GPS coordinates"
echo "      - NODEINFO_APP (port 4) - Node information"
echo "      - WAYPOINT_APP (port 8) - Waypoint and location data"
echo "      - RANGE_TEST_APP (port 66) - Range testing packets"
echo "      - TELEMETRY_APP (port 67) - Device telemetry data"
echo "      - TRACEROUTE_APP (port 70) - Route discovery and network path analysis"
echo ""
echo "The examples above demonstrate:"
echo "      - Different packet types and their decoding"
echo "      - Various routing scenarios (direct vs relayed packets)"
echo "      - Different hop counts and routing information"
echo "      - Real packets from the mesh network"
echo ""
echo "Install 'jq' for better JSON formatting: sudo apt install jq (Ubuntu/Debian) or brew install jq (macOS)"
