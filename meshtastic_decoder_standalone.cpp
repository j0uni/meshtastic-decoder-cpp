#include "aes_barebones.h"
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

class MeshtasticDecoderStandalone
{
  public:
	struct DecodedPacket
	{
		bool success;
		std::string error_message;

		// Header information
		uint32_t to_address;
		uint32_t from_address;
		uint32_t packet_id;
		uint8_t flags;
		uint8_t channel;
		uint8_t next_hop;
		uint8_t relay_node;

		// Port information
		uint8_t port;
		std::string app_name;

		// Position data (for POSITION_APP)
		double latitude;
		double longitude;
		int32_t altitude;
		uint32_t timestamp;

		// Node info data (for NODEINFO_APP)
		std::string node_id;
		std::string long_name;
		std::string short_name;
		std::string macaddr;
		std::string hw_model;
		std::string firmware_version;
		std::string mqtt_id;

		// Text message data (for TEXT_MESSAGE_APP)
		std::string text_message;
		std::string from_node;
		std::string to_node;

		// Traceroute data (for TRACEROUTE_APP)
		std::vector<uint32_t> route_nodes;
		std::string route_path;
		int route_count;
		
		// Telemetry data (for TELEMETRY_APP)
		std::string telemetry_info;
		std::string raw_telemetry_hex;
		
		// Skip and travel information
		uint8_t skip_count;
		bool heard_directly;
		uint8_t hop_limit;
		std::string routing_info;
		
		

		// Raw data
		std::string decrypted_payload_hex;
		std::string nonce_hex;
		std::string key_used;
	};

	// Main decoding function
	DecodedPacket decodePacket(const std::vector<uint8_t>& raw_data);

	// JSON output function
	std::string toJson(const DecodedPacket& packet);

	// Utility functions
	static std::vector<uint8_t> hexStringToBytes(const std::string& hex_string);
	static std::string bytesToHexString(const std::vector<uint8_t>& data);
	static std::string escapeJsonString(const std::string& str);
	static std::string formatDouble(double value, int precision = 7);

  private:
	// Default PSK key (Base64: 1PG7OiApB1nwvP+rz05pAQ==)
	static const std::vector<uint8_t> DEFAULT_PSK;

	// Header parsing
	bool parseHeader(const std::vector<uint8_t>& data, DecodedPacket& packet);

	// AES decryption
	bool decryptPayload(const std::vector<uint8_t>& encrypted_payload,
						const DecodedPacket& packet,
						std::vector<uint8_t>& decrypted);

	// Nonce construction
	std::vector<uint8_t> buildNonce(const DecodedPacket& packet);

	// Protobuf decoding
	bool decodeProtobuf(const std::vector<uint8_t>& data,
						DecodedPacket& packet);
	bool decodePosition(const std::vector<uint8_t>& data,
						DecodedPacket& packet);
	bool decodeTextMessage(const std::vector<uint8_t>& data,
						   DecodedPacket& packet);
	bool decodeNodeInfo(const std::vector<uint8_t>& data,
						DecodedPacket& packet);
	bool decodeTelemetry(const std::vector<uint8_t>& data,
						 DecodedPacket& packet);
	bool decodeTraceroute(const std::vector<uint8_t>& data,
						  DecodedPacket& packet);
	uint64_t decodeVarint(const std::vector<uint8_t>& data, size_t& offset);
	
	// Skip and routing calculation
	void calculateSkipAndRouting(DecodedPacket& packet);
};

// Default PSK key (Base64: 1PG7OiApB1nwvP+rz05pAQ==)
const std::vector<uint8_t> MeshtasticDecoderStandalone::DEFAULT_PSK = {
	0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
	0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

MeshtasticDecoderStandalone::DecodedPacket
MeshtasticDecoderStandalone::decodePacket(const std::vector<uint8_t>& raw_data)
{
	DecodedPacket result;
	result.success = false;

	// Initialize default values
	result.to_address = 0;
	result.from_address = 0;
	result.packet_id = 0;
	result.flags = 0;
	result.channel = 0;
	result.next_hop = 0;
	result.relay_node = 0;
	result.port = 0;
	result.app_name = "UNKNOWN";
	result.latitude = 0.0;
	result.longitude = 0.0;
	result.altitude = 0;
	result.timestamp = 0;
	result.node_id = "";
	result.long_name = "";
	result.short_name = "";
	result.macaddr = "";
	result.hw_model = "";
	result.firmware_version = "";
	result.mqtt_id = "";
	result.text_message = "";
	result.from_node = "";
	result.to_node = "";
	result.route_nodes.clear();
	result.route_path = "";
	result.route_count = 0;
	result.skip_count = 0;
	result.heard_directly = false;
	result.hop_limit = 0;
	result.routing_info = "";

	// Parse header
	if (!parseHeader(raw_data, result))
	{
		result.error_message = "Failed to parse packet header";
		return result;
	}
	
	// Calculate skip count and routing information
	calculateSkipAndRouting(result);

	// Extract payload
	if (raw_data.size() < 16)
	{
		result.error_message = "Packet too short for header";
		return result;
	}

	std::vector<uint8_t> encrypted_payload(raw_data.begin() + 16,
										   raw_data.end());

	// Decrypt payload
	std::vector<uint8_t> decrypted_payload;
	if (!decryptPayload(encrypted_payload, result, decrypted_payload))
	{
		result.error_message = "Failed to decrypt payload";
		return result;
	}

	// Store decrypted payload as hex
	result.decrypted_payload_hex = bytesToHexString(decrypted_payload);

	// Store nonce and key information
	std::vector<uint8_t> nonce = buildNonce(result);
	result.nonce_hex = bytesToHexString(nonce);
	result.key_used = "1PG7OiApB1nwvP+rz05pAQ==";

	// Parse protobuf
	if (decrypted_payload.size() < 2)
	{
		result.error_message = "Decrypted payload too short";
		return result;
	}

	// Extract port number and set app name
	// The first byte is a protobuf field number, the port is in the second byte
	result.port = decrypted_payload[1];
	switch (result.port)
	{
		case 1:
			result.app_name = "TEXT_MESSAGE_APP";
			break;
		case 3:
			result.app_name = "POSITION_APP";
			break;
		case 4:
			result.app_name = "NODEINFO_APP";
			break;
		case 8:
			result.app_name = "WAYPOINT_APP";
			break;
		case 66:
			result.app_name = "RANGE_TEST_APP";
			break;
		case 67:
			result.app_name = "TELEMETRY_APP";
			break;
		case 70:
			result.app_name = "TRACEROUTE_APP";
			break;
		default:
			result.app_name = "UNKNOWN_APP";
			break;
	}

	// Decode protobuf data based on app type
	if (!decodeProtobuf(decrypted_payload, result))
	{
		result.error_message = "Failed to decode protobuf data";
		return result;
	}

	// Set node_id from from_address (only if not already set by protobuf parsing)
	if (result.node_id.empty())
	{
		std::stringstream ss;
		ss << "!" << std::hex << std::setfill('0') << std::setw(8)
		   << result.from_address;
		result.node_id = ss.str();
	}

	result.success = true;
	return result;
}

bool MeshtasticDecoderStandalone::parseHeader(const std::vector<uint8_t>& data,
											  DecodedPacket& packet)
{
	if (data.size() < 16)
	{
		return false;
	}

	// Parse header fields (little-endian)
	packet.to_address =
	  data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
	packet.from_address =
	  data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
	packet.packet_id =
	  data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
	packet.flags = data[12];
	packet.channel = data[13];
	packet.next_hop = data[14];
	packet.relay_node = data[15];

	return true;
}

std::vector<uint8_t> MeshtasticDecoderStandalone::buildNonce(
  const DecodedPacket& packet)
{
	std::vector<uint8_t> nonce(16, 0);

	// Packet ID (4 bytes, little-endian)
	nonce[0] = packet.packet_id & 0xFF;
	nonce[1] = (packet.packet_id >> 8) & 0xFF;
	nonce[2] = (packet.packet_id >> 16) & 0xFF;
	nonce[3] = (packet.packet_id >> 24) & 0xFF;

	// Zero padding (4 bytes) - already zero

	// Sender Address (4 bytes, little-endian)
	nonce[8] = packet.from_address & 0xFF;
	nonce[9] = (packet.from_address >> 8) & 0xFF;
	nonce[10] = (packet.from_address >> 16) & 0xFF;
	nonce[11] = (packet.from_address >> 24) & 0xFF;

	// Zero padding (4 bytes) - already zero

	return nonce;
}

bool MeshtasticDecoderStandalone::decryptPayload(
  const std::vector<uint8_t>& encrypted_payload,
  const DecodedPacket& packet,
  std::vector<uint8_t>& decrypted)
{
	// Build nonce
	std::vector<uint8_t> nonce = buildNonce(packet);

	// Initialize AES
	AES128Barebones aes;
	aes.setKey(DEFAULT_PSK.data());

	// Decrypt
	decrypted.resize(encrypted_payload.size());
	aes.decryptCTR(encrypted_payload.data(),
				   decrypted.data(),
				   encrypted_payload.size(),
				   nonce.data());

	return true;
}

bool MeshtasticDecoderStandalone::decodeProtobuf(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	if (data.size() < 4)
	{
		return false;
	}

	// The structure is: 08 [port] 12 [length] [data]
	// 0x12 = field 2, wire type 2 (length-delimited)

	if (data[2] == 0x12)
	{
		uint8_t length = data[3];

		if (data.size() < 4 + static_cast<size_t>(length))
		{
			return false;
		}

		// Extract protobuf data
		std::vector<uint8_t> protobuf_data(data.begin() + 4,
										   data.begin() + 4 + length);

		// Decode based on app type
		switch (packet.port)
		{
			case 1: // TEXT_MESSAGE_APP
				return decodeTextMessage(data, packet);
			case 3: // POSITION_APP
				return decodePosition(protobuf_data, packet);
			case 4: // NODEINFO_APP
				return decodeNodeInfo(data, packet);
			case 8: // WAYPOINT_APP
				// For waypoint, just return success without decoding
				return true;
			case 66: // RANGE_TEST_APP
				// For range test, just return success without decoding
				return true;
			case 67: // TELEMETRY_APP
				return decodeTelemetry(protobuf_data, packet);
			case 70: // TRACEROUTE_APP
				return decodeTraceroute(protobuf_data, packet);
			default:
				// For unknown apps, just return success without decoding
				return true;
		}
	}

	return true;
}

bool MeshtasticDecoderStandalone::decodePosition(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Extract coordinates from the position data
	// Based on our analysis, the coordinates are stored as 32-bit little-endian
	// values at specific offsets in the position data

	if (data.size() >= 15)
	{
		// Latitude is at offset 1-4 (little-endian)
		uint32_t latitude_i =
		  data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
		packet.latitude = latitude_i / 1e7;

		// Longitude is at offset 6-9 (little-endian)
		uint32_t longitude_i =
		  data[6] | (data[7] << 8) | (data[8] << 16) | (data[9] << 24);
		packet.longitude = longitude_i / 1e7;

		// Altitude is at offset 11-12 (little-endian, 16-bit)
		packet.altitude = data[11] | (data[12] << 8);

		// Time is at offset 13-14 (little-endian, 16-bit)
		packet.timestamp = data[13] | (data[14] << 8);
	}

	return true;
}

bool MeshtasticDecoderStandalone::decodeTextMessage(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Structure: 08 01 12 [length] [text_data]
	// The text message is directly in the protobuf data, not nested

	if (data.size() >= 4 && data[0] == 0x08 && data[1] == 0x01 &&
		data[2] == 0x12)
	{
		uint8_t length = data[3];

		if (data.size() >= 4 + static_cast<size_t>(length) && length > 0)
		{
			// Extract text directly from bytes 4 to 4+length
			std::string text(data.begin() + 4, data.begin() + 4 + length);

			// The text is already in UTF-8 format, so we can use it directly
			// Just ensure it's null-terminated
			packet.text_message = text;
		}
	}

	return true;
}

bool MeshtasticDecoderStandalone::decodeNodeInfo(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Parse User protobuf message
	// Structure: 08 04 12 [length] [user_protobuf_data]
	// The protobuf data contains User message fields


	if (data.size() >= 4 && data[0] == 0x08 && data[1] == 0x04 &&
		data[2] == 0x12)
	{
		uint8_t length = data[3];

		if (data.size() >= 4 + static_cast<size_t>(length) && length > 0)
		{
			// Extract User protobuf data
			std::vector<uint8_t> user_data(data.begin() + 4,
										   data.begin() + 4 + length);

			// Parse User protobuf fields according to mesh.proto
			size_t offset = 0;
			while (offset < user_data.size())
			{
				if (offset >= user_data.size())
					break;

				// Read field tag and wire type
				uint64_t tag_wire_type = decodeVarint(user_data, offset);
				if (tag_wire_type == 0)
					break;

				uint8_t field_number = tag_wire_type >> 3;
				uint8_t wire_type = tag_wire_type & 0x07;

				// Parse field based on tag number and wire type
				switch (field_number)
				{
					case 1: // id (string)
						if (wire_type == 2)
						{ // Length-delimited
							uint64_t field_length =
							  decodeVarint(user_data, offset);
							if (field_length > 0 &&
								offset + field_length <= user_data.size())
							{
								std::string field_data(
								  user_data.begin() + offset,
								  user_data.begin() + offset + field_length);
								packet.node_id = field_data;
								offset += field_length;
							}
						}
						break;

					case 2: // long_name (string)
						if (wire_type == 2)
						{ // Length-delimited
							uint64_t field_length =
							  decodeVarint(user_data, offset);
							if (field_length > 0 &&
								offset + field_length <= user_data.size())
							{
								std::string field_data(
								  user_data.begin() + offset,
								  user_data.begin() + offset + field_length);
								packet.long_name = field_data;
								offset += field_length;
							}
						}
						break;

					case 3: // short_name (string)
						if (wire_type == 2)
						{ // Length-delimited
							uint64_t field_length =
							  decodeVarint(user_data, offset);
							if (field_length > 0 &&
								offset + field_length <= user_data.size())
							{
								std::string field_data(
								  user_data.begin() + offset,
								  user_data.begin() + offset + field_length);
								packet.short_name = field_data;
								offset += field_length;
							}
						}
						break;

					case 4: // macaddr (bytes)
						if (wire_type == 2)
						{ // Length-delimited
							uint64_t field_length =
							  decodeVarint(user_data, offset);
							if (field_length > 0 &&
								offset + field_length <= user_data.size())
							{
								std::vector<uint8_t> mac_bytes(
								  user_data.begin() + offset,
								  user_data.begin() + offset + field_length);
								if (mac_bytes.size() == 6)
								{
									char mac_str[18];
									snprintf(mac_str,
											 sizeof(mac_str),
											 "%02X:%02X:%02X:%02X:%02X:%02X",
											 mac_bytes[0],
											 mac_bytes[1],
											 mac_bytes[2],
											 mac_bytes[3],
											 mac_bytes[4],
											 mac_bytes[5]);
									packet.macaddr = std::string(mac_str);
								}
								else
								{
									// Convert to hex string
									std::string hex_mac;
									for (uint8_t b : mac_bytes)
									{
										char hex[3];
										snprintf(hex, sizeof(hex), "%02X", b);
										hex_mac += hex;
									}
									packet.macaddr = hex_mac;
								}
								offset += field_length;
							}
						}
						break;

					case 5: // hw_model (enum)
						if (wire_type == 0)
						{ // Varint
							uint64_t hw_model = decodeVarint(user_data, offset);
							// Hardware model mapping from mesh.proto
							switch (hw_model)
							{
								case 0:
									packet.hw_model = "UNSET";
									break;
								case 1:
									packet.hw_model = "TLORA_V2";
									break;
								case 2:
									packet.hw_model = "TLORA_V1";
									break;
								case 3:
									packet.hw_model = "TLORA_V2_1_1P6";
									break;
								case 4:
									packet.hw_model = "TBEAM";
									break;
								case 5:
									packet.hw_model = "HELTEC_V2_0";
									break;
								case 6:
									packet.hw_model = "TBEAM_V0P7";
									break;
								case 7:
									packet.hw_model = "T_ECHO";
									break;
								case 8:
									packet.hw_model = "TLORA_V1_1P3";
									break;
								case 9:
									packet.hw_model = "RAK4631";
									break;
								case 10:
									packet.hw_model = "HELTEC_V2_1";
									break;
								case 11:
									packet.hw_model = "HELTEC_V1";
									break;
								case 12:
									packet.hw_model = "LILYGO_TBEAM_S3_CORE";
									break;
								case 13:
									packet.hw_model = "RAK11200";
									break;
								case 14:
									packet.hw_model = "NANO_G1";
									break;
								case 15:
									packet.hw_model = "TLORA_V2_1_1P8";
									break;
								case 16:
									packet.hw_model = "TLORA_T3_S3";
									break;
								case 17:
									packet.hw_model = "NANO_G1_EXPLORER";
									break;
								case 18:
									packet.hw_model = "NANO_G2_ULTRA";
									break;
								case 19:
									packet.hw_model = "LORA_TYPE";
									break;
								case 20:
									packet.hw_model = "WIPHONE";
									break;
								case 21:
									packet.hw_model = "WIO_WM1110";
									break;
								case 22:
									packet.hw_model = "RAK2560";
									break;
								case 23:
									packet.hw_model = "HELTEC_HRU_3601";
									break;
								default:
									packet.hw_model =
									  "UNKNOWN_" + std::to_string(hw_model);
									break;
							}
						}
						break;

					case 6: // is_licensed (bool)
						if (wire_type == 0)
						{ // Varint
							uint64_t licensed = decodeVarint(user_data, offset);
							packet.firmware_version = licensed ? "Yes" : "No";
						}
						break;

					case 7: // role (enum)
						if (wire_type == 0)
						{ // Varint
							uint64_t role = decodeVarint(user_data, offset);
							switch (role)
							{
								case 0:
									packet.mqtt_id = "CLIENT";
									break;
								case 1:
									packet.mqtt_id = "CLIENT_MUTE";
									break;
								case 2:
									packet.mqtt_id = "ROUTER";
									break;
								case 3:
									packet.mqtt_id = "ROUTER_CLIENT";
									break;
								case 4:
									packet.mqtt_id = "REPEATER";
									break;
								case 5:
									packet.mqtt_id = "TRACKER";
									break;
								case 6:
									packet.mqtt_id = "SENSOR";
									break;
								default:
									packet.mqtt_id =
									  "UNKNOWN_" + std::to_string(role);
									break;
							}
						}
						break;

					default:
						// Skip unknown fields
						if (wire_type == 0)
						{
							decodeVarint(user_data, offset);
						}
						else if (wire_type == 2)
						{
							uint64_t field_length =
							  decodeVarint(user_data, offset);
							offset += field_length;
						}
						else if (wire_type == 5)
						{
							offset += 4; // Skip fixed32
						}
						else
						{
							offset++;
						}
						break;
				}
			}
		}
	}

	return true;
}

bool MeshtasticDecoderStandalone::decodeTelemetry(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Parse Telemetry protobuf message
	// Structure: [telemetry_data]
	// The protobuf data contains Telemetry message fields

	if (data.empty())
	{
		return false;
	}

	// For now, just store the raw telemetry data
	// In a full implementation, we would parse the protobuf fields
	std::stringstream ss;
	ss << "Telemetry data (" << data.size() << " bytes)";
	packet.telemetry_info = ss.str();

	// Store raw hex data for debugging
	ss.str("");
	ss << std::hex << std::setfill('0');
	for (uint8_t byte : data)
	{
		ss << std::setw(2) << static_cast<int>(byte) << " ";
	}
	packet.raw_telemetry_hex = ss.str();

	return true;
}

bool MeshtasticDecoderStandalone::decodeTraceroute(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Parse RouteDiscovery protobuf message according to Meshtastic mesh.proto specification
	// RouteDiscovery message fields:
	// - repeated fixed32 route = 2;  // List of node IDs in the route path
	
	size_t offset = 0;
	std::vector<uint32_t> route;
	
	// The data should be the RouteDiscovery protobuf: 12 01 19
	// 12 = field 2, wire type 2 (length-delimited)
	// 01 = length 1
	// 19 = single byte value (25 decimal)
	
	while (offset < data.size())
	{
		if (offset >= data.size())
			break;
		
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		if (field_number == 2 && wire_type == 2)
		{
			// Field 2: repeated fixed32 route (length-delimited)
			uint64_t field_length = decodeVarint(data, offset);
			
			if (field_length > 0 && offset + field_length <= data.size())
			{
				// Extract the route data
				std::vector<uint8_t> route_data(data.begin() + offset,
											   data.begin() + offset + field_length);
				
				// According to mesh.proto, route field is "repeated fixed32"
				// This means it should contain 32-bit node IDs, not single bytes
				// Parse as packed fixed32 values (little-endian)
				if (route_data.size() % 4 == 0 && route_data.size() >= 4)
				{
					// Parse as packed fixed32 values
					for (size_t i = 0; i < route_data.size(); i += 4)
					{
						uint32_t node_id = route_data[i] |
										   (route_data[i + 1] << 8) |
										   (route_data[i + 2] << 16) |
										   (route_data[i + 3] << 24);
						route.push_back(node_id);
					}
				}
				else
				{
					// If not multiple of 4 bytes, this might be a different format
					// or the data might be corrupted. Log this case for debugging.
					// For now, skip this route data as it doesn't match expected format.
					// This handles cases where we have single bytes like 0x19 (25)
					// which are not valid 32-bit node IDs.
				}
				
				offset += field_length;
			}
		}
		else
		{
			// Skip unknown fields
			if (wire_type == 0)
			{
				decodeVarint(data, offset);
			}
			else if (wire_type == 2)
			{
				uint64_t field_length = decodeVarint(data, offset);
				offset += field_length;
			}
			else if (wire_type == 5)
			{
				offset += 4; // Skip fixed32
			}
			else
			{
				break; // Unknown wire type
			}
		}
	}
	
	// Store route information
	packet.route_nodes = route;
	packet.route_count = route.size();
	
	// Format route as readable path
	if (!route.empty())
	{
		std::stringstream route_path_ss;
		for (size_t i = 0; i < route.size(); ++i)
		{
			if (i > 0)
				route_path_ss << " → ";
			
			// Format node ID as hex string
			std::stringstream node_ss;
			node_ss << "!" << std::hex << std::setfill('0') << std::setw(8) << route[i];
			route_path_ss << node_ss.str();
		}
		packet.route_path = route_path_ss.str();
	}
	
	return true;
}

uint64_t MeshtasticDecoderStandalone::decodeVarint(
  const std::vector<uint8_t>& data,
  size_t& offset)
{
	uint64_t result = 0;
	int shift = 0;

	while (offset < data.size())
	{
		uint8_t byte = data[offset++];
		result |= (uint64_t)(byte & 0x7F) << shift;

		if ((byte & 0x80) == 0)
		{
			return result;
		}

		shift += 7;
		if (shift >= 64)
		{
			// Varint too long
			return 0;
		}
	}

	return 0;
}

void MeshtasticDecoderStandalone::calculateSkipAndRouting(DecodedPacket& packet)
{
	// In Meshtastic protocol, the hop limit field in flags represents the remaining
	// hops the packet can take. A packet is heard directly when it hasn't been
	// relayed yet, which means it still has its full hop limit remaining.
	
	// Extract hop limit from flags (bits 0-2: first 3 bits)
	// According to Meshtastic protocol documentation
	packet.hop_limit = packet.flags & 0x07;
	
	// Extract hop start from flags (bits 5-7: original hop limit)
	uint8_t hop_start = (packet.flags >> 5) & 0x07;
	
	// Calculate hops taken based on Meshtastic protocol
	// hops_taken = hop_start - hop_limit
	// This works for both direct and relayed packets
	packet.skip_count = hop_start - packet.hop_limit;
	
	// Determine if packet was heard directly
	// A packet is "direct" if it's a unicast message (not broadcast) between specific nodes
	// This indicates direct communication between two nodes, regardless of mesh routing
	packet.heard_directly = (packet.to_address != 0xFFFFFFFF);
	
	// Build routing information string
	std::stringstream routing_ss;
	routing_ss << "Hops: " << (int)packet.skip_count << "/" << (int)hop_start;
	
	if (packet.heard_directly) {
		routing_ss << " (Direct)";
	} else {
		routing_ss << " (Relayed)";
		if (packet.next_hop != 0) {
			routing_ss << " [Next: 0x" << std::hex << std::setfill('0') 
					   << std::setw(8) << packet.next_hop << "]";
		}
	}
	
	if (packet.relay_node != 0) {
		routing_ss << " [Relay: 0x" << std::hex << std::setfill('0') 
				   << std::setw(8) << packet.relay_node << "]";
	}
	
	packet.routing_info = routing_ss.str();
}

std::string MeshtasticDecoderStandalone::toJson(const DecodedPacket& packet)
{
	std::stringstream json;

	json << "{\n";
	json << "  \"success\": " << (packet.success ? "true" : "false") << ",\n";

	if (!packet.success)
	{
		json << "  \"error\": \"" << escapeJsonString(packet.error_message)
			 << "\"\n";
	}
	else
	{
		json << "  \"header\": {\n";
		json << "    \"to_address\": \"0x" << std::uppercase << std::hex << std::setfill('0')
			 << std::setw(8) << packet.to_address << " (" << std::dec << packet.to_address << ")\",\n";
		json << "    \"from_address\": \"0x" << std::uppercase << std::hex << std::setfill('0')
			 << std::setw(8) << packet.from_address << " (" << std::dec << packet.from_address << ")\",\n";
		json << "    \"packet_id\": \"0x" << std::uppercase << std::hex << std::setfill('0')
			 << std::setw(8) << packet.packet_id << " (" << std::dec << packet.packet_id << ")\",\n";
		json << "    \"flags\": \"0x" << std::uppercase << std::hex << std::setfill('0')
			 << std::setw(2) << (int)packet.flags << "\",\n";
		json << "    \"channel\": " << std::dec << (int)packet.channel << ",\n";
		json << "    \"next_hop\": " << (int)packet.next_hop << ",\n";
		json << "    \"relay_node\": " << (int)packet.relay_node << "\n";
		json << "  },\n";
		
		json << "  \"routing\": {\n";
		json << "    \"skip_count\": " << (int)packet.skip_count << ",\n";
		json << "    \"hop_limit\": " << (int)packet.hop_limit << ",\n";
		json << "    \"heard_directly\": " << (packet.heard_directly ? "true" : "false") << ",\n";
		json << "    \"routing_info\": \"" << escapeJsonString(packet.routing_info) << "\"\n";
		json << "  },\n";

		json << "  \"port\": " << (int)packet.port << ",\n";
		json << "  \"app_name\": \"" << escapeJsonString(packet.app_name)
			 << "\",\n";
		json << "  \"nonce_hex\": \"" << packet.nonce_hex << "\",\n";
		json << "  \"key_used\": \"" << packet.key_used << "\",\n";
		
		

		// Output app-specific data
		if (packet.port == 3)
		{ // POSITION_APP
			json << "  \"position\": {\n";
			json << "    \"latitude\": " << formatDouble(packet.latitude)
				 << ",\n";
			json << "    \"longitude\": " << formatDouble(packet.longitude)
				 << ",\n";
			json << "    \"altitude\": " << packet.altitude << ",\n";
			json << "    \"timestamp\": " << packet.timestamp << "\n";
			json << "  },\n";
			json << "  \"google_maps_url\": \"https://www.google.com/maps?q="
				 << packet.latitude << "," << packet.longitude << "\",\n";
		}
		else if (packet.port == 1)
		{ // TEXT_MESSAGE_APP
			json << "  \"text_message\": \""
				 << escapeJsonString(packet.text_message) << "\",\n";
		}
		else if (packet.port == 4)
		{ // NODEINFO_APP
			json << "  \"node_info\": {\n";
			bool first = true;
			if (!packet.node_id.empty())
			{
				if (!first)
					json << ",\n";
				json << "    \"node_id\": \""
					 << escapeJsonString(packet.node_id) << "\"";
				first = false;
			}
			if (!packet.long_name.empty())
			{
				if (!first)
					json << ",\n";
				json << "    \"long_name\": \""
					 << escapeJsonString(packet.long_name) << "\"";
				first = false;
			}
			if (!packet.short_name.empty())
			{
				if (!first)
					json << ",\n";
				json << "    \"short_name\": \""
					 << escapeJsonString(packet.short_name) << "\"";
				first = false;
			}
			if (!packet.macaddr.empty())
			{
				if (!first)
					json << ",\n";
				json << "    \"macaddr\": \""
					 << escapeJsonString(packet.macaddr) << "\"";
				first = false;
			}
			if (!packet.hw_model.empty())
			{
				if (!first)
					json << ",\n";
				json << "    \"hw_model\": \""
					 << escapeJsonString(packet.hw_model) << "\"";
				first = false;
			}
			if (!packet.firmware_version.empty())
			{
				if (!first)
					json << ",\n";
				json << "    \"firmware_version\": \""
					 << escapeJsonString(packet.firmware_version) << "\"";
				first = false;
			}
			if (!packet.mqtt_id.empty())
			{
				if (!first)
					json << ",\n";
				json << "    \"mqtt_id\": \""
					 << escapeJsonString(packet.mqtt_id) << "\"";
				first = false;
			}
			json << "\n  },\n";
		}
		else if (packet.port == 67)
		{ // TELEMETRY_APP
			json << "  \"telemetry\": {\n";
			json << "    \"info\": \"" << escapeJsonString(packet.telemetry_info) << "\",\n";
			json << "    \"raw_hex\": \"" << escapeJsonString(packet.raw_telemetry_hex) << "\"\n";
			json << "  },\n";
		}
		else if (packet.port == 70)
		{ // TRACEROUTE_APP
			json << "  \"traceroute\": {\n";
			json << "    \"route_count\": " << packet.route_count << ",\n";
			json << "    \"route_path\": \"" << escapeJsonString(packet.route_path) << "\",\n";
			json << "    \"route_nodes\": [";
			for (size_t i = 0; i < packet.route_nodes.size(); ++i)
			{
				if (i > 0)
					json << ", ";
				json << "\"0x" << std::hex << std::setfill('0') << std::setw(8) << packet.route_nodes[i] << "\"";
			}
			json << "]\n  },\n";
		}

		json << "  \"decrypted_payload\": \""
			 << escapeJsonString(packet.decrypted_payload_hex) << "\"\n";
	}

	json << "}";

	return json.str();
}

std::vector<uint8_t> MeshtasticDecoderStandalone::hexStringToBytes(
  const std::string& hex_string)
{
	std::vector<uint8_t> bytes;
	std::stringstream ss(hex_string);
	std::string byte_str;

	while (ss >> byte_str)
	{
		if (byte_str.length() == 2)
		{
			bytes.push_back(
			  static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16)));
		}
	}

	return bytes;
}

std::string MeshtasticDecoderStandalone::bytesToHexString(
  const std::vector<uint8_t>& data)
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');

	for (size_t i = 0; i < data.size(); ++i)
	{
		if (i > 0)
			ss << " ";
		ss << std::setw(2) << (int)data[i];
	}

	return ss.str();
}

std::string MeshtasticDecoderStandalone::escapeJsonString(
  const std::string& str)
{
	std::string escaped;
	for (char c : str)
	{
		switch (c)
		{
			case '"':
				escaped += "\\\"";
				break;
			case '\\':
				escaped += "\\\\";
				break;
			case '\b':
				escaped += "\\b";
				break;
			case '\f':
				escaped += "\\f";
				break;
			case '\n':
				escaped += "\\n";
				break;
			case '\r':
				escaped += "\\r";
				break;
			case '\t':
				escaped += "\\t";
				break;
			default:
				if (c >= 32 && c <= 126)
				{ // Printable ASCII
					escaped += c;
				}
				else
				{ // Non-printable characters
					char hex[8];
					snprintf(hex, sizeof(hex), "\\u%04x", (unsigned char)c);
					escaped += hex;
				}
				break;
		}
	}
	return escaped;
}

std::string MeshtasticDecoderStandalone::formatDouble(double value,
													  int precision)
{
	std::stringstream ss;
	ss << std::fixed << std::setprecision(precision) << value;
	return ss.str();
}

// Main function
int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cerr << "Usage: " << argv[0] << " <hex_data>\n";
		std::cerr
		  << "Example: " << argv[0]
		  << " \"FF FF FF FF 5C CB 2A DB 2A 28 5C 47 E5 08 00 B8 0F 56 74 92 9D ED 42 E9 C1 E6 40 DA 28 34 8D 14 C4 F1 FF 72 90 AD 08\"\n";
		return 1;
	}

	std::string hex_input = argv[1];

	// Convert hex string to bytes
	std::vector<uint8_t> raw_data =
	  MeshtasticDecoderStandalone::hexStringToBytes(hex_input);

	if (raw_data.empty())
	{
		std::cerr << "Error: Invalid hex data provided\n";
		return 1;
	}

	// Decode the packet
	MeshtasticDecoderStandalone decoder;
	MeshtasticDecoderStandalone::DecodedPacket result =
	  decoder.decodePacket(raw_data);

	// Output JSON
	std::cout << decoder.toJson(result) << std::endl;

	return result.success ? 0 : 1;
}
