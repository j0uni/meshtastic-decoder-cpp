#include "meshtastic_decoder.h"
#include "aes_barebones.h"
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

const std::vector<uint8_t> MeshtasticDecoder::DEFAULT_PSK = {
	0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
	0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

MeshtasticDecoder::DecodedPacket
MeshtasticDecoder::decodePacket(const std::vector<uint8_t>& raw_data)
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
	result.sats_in_view = 0;
	result.sats_in_use = 0;
	result.ground_speed = 0;
	result.ground_track = -1.0; // Use -1.0 as sentinel for "not set"
	result.gps_accuracy = 0;
	result.pdop = 0.0;
	result.hdop = 0.0;
	result.vdop = 0.0;
	result.fix_quality = 0;
	result.fix_type = 0;
	result.precision_bits = 0;
	result.altitude_hae = 0;
	result.altitude_geoidal_separation = 0;
	result.location_source = 0;
	result.altitude_source = 0;
	result.timestamp_millis_adjust = 0;
	result.sensor_id = 0;
	result.next_update = 0;
	result.seq_number = 0;
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
	result.route_back_nodes.clear();
	result.snr_towards.clear();
	result.snr_back.clear();
	result.route_path = "";
	result.route_back_path = "";
	result.route_count = 0;
	result.route_back_count = 0;
	result.route_type = "";
	result.skip_count = 0;
	result.heard_directly = false;
	result.hop_limit = 0;
	result.routing_info = "";
	result.telemetry_type = "";
	result.telemetry_time = 0;
	result.battery_level = 0;
	result.voltage = 0.0f;
	result.channel_utilization = 0.0f;
	result.air_util_tx = 0.0f;
	result.uptime_seconds = 0;
	result.temperature = 0.0f;
	result.relative_humidity = 0.0f;
	result.barometric_pressure = 0.0f;
	result.gas_resistance = 0.0f;
	result.current = 0.0f;
	result.iaq = 0;
	result.distance = 0.0f;
	result.lux = 0.0f;
	result.white_lux = 0.0f;
	result.ir_lux = 0.0f;
	result.uv_lux = 0.0f;
	result.wind_direction = 0;
	result.wind_speed = 0.0f;
	result.weight = 0.0f;
	result.wind_gust = 0.0f;
	result.wind_lull = 0.0f;
	result.radiation = 0.0f;
	result.rainfall_1h = 0.0f;
	result.rainfall_24h = 0.0f;
	result.soil_moisture = 0;
	result.soil_temperature = 0.0f;
	result.pm10_standard = 0;
	result.pm25_standard = 0;
	result.pm100_standard = 0;
	result.pm10_environmental = 0;
	result.pm25_environmental = 0;
	result.pm100_environmental = 0;
	result.particles_03um = 0;
	result.particles_05um = 0;
	result.particles_10um = 0;
	result.particles_25um = 0;
	result.particles_50um = 0;
	result.particles_100um = 0;
	result.co2 = 0;
	result.co2_temperature = 0.0f;
	result.co2_humidity = 0.0f;
	result.form_formaldehyde = 0.0f;
	result.form_humidity = 0.0f;
	result.form_temperature = 0.0f;
	result.ch1_voltage = result.ch1_current = 0.0f;
	result.ch2_voltage = result.ch2_current = 0.0f;
	result.ch3_voltage = result.ch3_current = 0.0f;
	result.ch4_voltage = result.ch4_current = 0.0f;
	result.ch5_voltage = result.ch5_current = 0.0f;
	result.ch6_voltage = result.ch6_current = 0.0f;
	result.ch7_voltage = result.ch7_current = 0.0f;
	result.ch8_voltage = result.ch8_current = 0.0f;
	result.num_packets_tx = 0;
	result.num_packets_rx = 0;
	result.num_packets_rx_bad = 0;
	result.num_online_nodes = 0;
	result.num_total_nodes = 0;
	result.num_rx_dupe = 0;
	result.num_tx_relay = 0;
	result.num_tx_relay_canceled = 0;
	result.heap_total_bytes = 0;
	result.heap_free_bytes = 0;
	result.num_tx_dropped = 0;
	result.heart_bpm = 0;
	result.spO2 = 0;
	result.body_temperature = 0.0f;
	result.freemem_bytes = 0;
	result.diskfree1_bytes = 0;
	result.diskfree2_bytes = 0;
	result.diskfree3_bytes = 0;
	result.load1 = 0;
	result.load5 = 0;
	result.load15 = 0;
	result.host_user_string = "";

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

	// Check if payload is already unencrypted (starts with 0x08 = protobuf field 1 tag)
	// Unencrypted packets have the protobuf data directly in the payload
	std::vector<uint8_t> decrypted_payload;
	if (encrypted_payload.size() > 0 && encrypted_payload[0] == 0x08)
	{
		// Payload is already unencrypted - use it directly
		decrypted_payload = encrypted_payload;
	}
	else
	{
		// Decrypt payload
		if (!decryptPayload(encrypted_payload, result, decrypted_payload))
		{
			result.error_message = "Failed to decrypt payload";
			return result;
		}
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

	// Verify decryption was successful by checking if payload starts with expected structure
	// Valid Meshtastic packets should start with 0x08 (field 1 tag for portnum) or have it somewhere in the first few bytes
	// If decryption failed, the payload will be garbage and won't have this structure
	bool has_valid_structure = false;
	if (decrypted_payload.size() > 0 && decrypted_payload[0] == 0x08) {
		has_valid_structure = true;
	} else {
		// Scan first 16 bytes for the 0x08 tag (field 1 tag)
		for (size_t i = 0; i < decrypted_payload.size() && i < 16; i++) {
			if (decrypted_payload[i] == 0x08) {
				has_valid_structure = true;
				break;
			}
		}
	}
	
	if (!has_valid_structure) {
		result.error_message = "Decryption failed - payload doesn't have valid protobuf structure (missing field 1 tag 0x08)";
		return result;
	}

	// Extract port number and set app name
	// The Data protobuf message structure:
	// Field 1 (portnum): tag byte 0x08 (field 1, wire type 0 = varint), then port value as varint
	// Field 2 (payload): tag byte 0x12 (field 2, wire type 2 = length-delimited), then length, then data
	// So we need to parse the port as a varint, not read it directly
	size_t offset = 0;
	if (decrypted_payload.size() > 0 && decrypted_payload[0] == 0x08) {
		// Field 1 tag (0x08 = field 1, wire type 0)
		offset = 1;
		if (offset < decrypted_payload.size()) {
			// Decode port as varint
			result.port = decodeVarint(decrypted_payload, offset);
		} else {
			result.port = 0;
		}
	} else {
		// Payload doesn't start with 0x08, scan for it
		result.port = 0;
		for (size_t i = 0; i < decrypted_payload.size() - 1; i++) {
			if (decrypted_payload[i] == 0x08) {
				// Found field 1 tag, decode varint
				offset = i + 1;
				if (offset < decrypted_payload.size()) {
					result.port = decodeVarint(decrypted_payload, offset);
					break;
				}
			}
		}
		// If port field not found, this is invalid - don't guess from random bytes
		if (result.port == 0) {
			result.error_message = "Port field (0x08 tag) not found in decrypted payload";
			return result;
		}
	}
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

	// Decode MeshPacket protobuf fields (if present in decrypted payload)
	// This extracts fields like relay_node (field 19) and next_hop (field 18) from the MeshPacket structure
	decodeMeshPacketFields(decrypted_payload, result);
	
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

bool MeshtasticDecoder::parseHeader(const std::vector<uint8_t>& data,
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

std::vector<uint8_t> MeshtasticDecoder::buildNonce(
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

bool MeshtasticDecoder::decryptPayload(
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

bool MeshtasticDecoder::decodeProtobuf(
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
				// For traceroute, the protobuf_data is the Routing message
				// (field 2 of Data message contains the Routing message)
				return decodeTraceroute(protobuf_data, packet);
			default:
				// For unknown apps, just return success without decoding
				return true;
		}
	}

	return true;
}

void MeshtasticDecoder::decodeMeshPacketFields(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Decode MeshPacket protobuf fields from the decrypted payload
	// MeshPacket structure may contain additional routing information
	// Fields we're interested in:
	// - field 18: next_hop (uint32 varint in protobuf) - represents last byte of next hop node
	// - field 19: relay_node (uint32 varint in protobuf) - represents last byte of relay node
	// Note: Protobuf defines these as uint32, but semantically they represent the last byte
	// of the node number. We decode the full uint32 value and extract the last byte.
	
	if (data.empty())
	{
		return;
	}
	
	size_t offset = 0;
	
	// Parse MeshPacket fields
	while (offset < data.size())
	{
		if (offset >= data.size())
			break;
		
		// Read field tag and wire type
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 18: // next_hop (uint32 varint) - last byte of next hop node
				if (wire_type == 0) // Varint
				{
					uint64_t next_hop_val = decodeVarint(data, offset);
					// Protobuf defines this as uint32, but semantically it represents
					// the last byte of the node number. Decode full uint32 and extract last byte.
					// Only update if we got a non-zero value (0 means not set)
					if (next_hop_val > 0)
					{
						packet.next_hop = (next_hop_val & 0xFF);
					}
				}
				break;
			
			case 19: // relay_node (uint32 varint) - last byte of relay node
				if (wire_type == 0) // Varint
				{
					uint64_t relay_node_val = decodeVarint(data, offset);
					// Protobuf defines this as uint32, but semantically it represents
					// the last byte of the node number. Decode full uint32 and extract last byte.
					// Only update if we got a non-zero value (0 means not set)
					if (relay_node_val > 0)
					{
						packet.relay_node = (relay_node_val & 0xFF);
					}
				}
				break;
			
			default:
				// Skip other fields - we only care about routing fields here
				// The actual Data message decoding happens in decodeProtobuf
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
					offset++;
				}
				break;
		}
	}
}

bool MeshtasticDecoder::decodePosition(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Parse Position protobuf message according to Meshtastic mesh.proto
	// Based on actual packet analysis:
	// - field 1: latitude_i (fixed32) - latitude * 1e7
	// - field 2: longitude_i (fixed32) - longitude * 1e7
	// - field 3: altitude (int32 varint) - altitude in meters
	// - field 4: time (fixed32) - timestamp
	// - field 5: location_source (enum varint)
	// - field 11: precision_bits (uint32 varint)
	// - field 15: altitude_hae (int32 varint) - altitude above ellipsoid
	// - field 16: altitude_geoidal_separation (int32 varint)
	// - field 19: PDOP (uint32 varint) - Position Dilution of Precision
	// - field 23: HDOP (uint32 varint) - Horizontal Dilution of Precision
	// - field 9: next_hop (uint32 varint)
	// Additional fields may include sats_in_view, sats_in_use, ground_speed, etc.
	
	if (data.empty())
	{
		return false;
	}
	
	size_t offset = 0;
	
	while (offset < data.size())
	{
		if (offset >= data.size())
			break;
		
		// Read field tag and wire type
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		// Parse field based on tag number and wire type
		switch (field_number)
		{
			case 1: // latitude_i (fixed32)
				if (wire_type == 5) // Fixed32
				{
					if (offset + 4 <= data.size())
					{
						uint32_t latitude_i = data[offset] |
											   (data[offset + 1] << 8) |
											   (data[offset + 2] << 16) |
											   (data[offset + 3] << 24);
						// Convert to signed int32, then to degrees
						int32_t lat_signed = (int32_t)latitude_i;
						packet.latitude = lat_signed / 1e7;
						offset += 4;
					}
				}
				break;
			
			case 2: // longitude_i (fixed32)
				if (wire_type == 5) // Fixed32
				{
					if (offset + 4 <= data.size())
					{
						uint32_t longitude_i = data[offset] |
												(data[offset + 1] << 8) |
												(data[offset + 2] << 16) |
												(data[offset + 3] << 24);
						// Convert to signed int32, then to degrees
						int32_t lon_signed = (int32_t)longitude_i;
						packet.longitude = lon_signed / 1e7;
						offset += 4;
					}
				}
				break;
			
			case 3: // altitude (int32 varint) - altitude in meters (signed)
				if (wire_type == 0) // Varint
				{
					uint64_t alt_varint = decodeVarint(data, offset);
					// Convert varint to signed int32
					// Mask to 32 bits and cast to int32_t for proper sign extension
					uint32_t alt_unsigned = alt_varint & 0xFFFFFFFF;
					// Cast to int32_t - compiler handles sign extension
					packet.altitude = (int32_t)alt_unsigned;
				}
				break;
			
			case 4: // time (fixed32) - timestamp or other field
				if (wire_type == 5) // Fixed32
				{
					if (offset + 4 <= data.size())
					{
						// Skip this field for now - might be timestamp or other data
						offset += 4;
					}
				}
				break;
			
			case 5: // location_source (enum varint)
				if (wire_type == 0) // Varint
				{
					packet.location_source = decodeVarint(data, offset);
				}
				break;
			
			case 6: // altitude_source (enum varint)
				if (wire_type == 0) // Varint
				{
					packet.altitude_source = decodeVarint(data, offset);
				}
				break;
			
			case 7: // timestamp (fixed32) - positional timestamp in epoch seconds
				if (wire_type == 5) // Fixed32
				{
					if (offset + 4 <= data.size())
					{
						uint32_t ts = data[offset] |
									  (data[offset + 1] << 8) |
									  (data[offset + 2] << 16) |
									  (data[offset + 3] << 24);
						packet.timestamp = ts;
						offset += 4;
					}
				}
				break;
			
			case 8: // timestamp_millis_adjust (int32 varint)
				if (wire_type == 0) // Varint
				{
					uint64_t adjust_varint = decodeVarint(data, offset);
					uint32_t adjust_unsigned = adjust_varint & 0xFFFFFFFF;
					packet.timestamp_millis_adjust = (int32_t)adjust_unsigned;
				}
				break;
			
			case 9: // altitude_hae (sint32 varint) - HAE altitude in meters
				if (wire_type == 0) // Varint
				{
					uint64_t hae_varint = decodeVarint(data, offset);
					uint32_t hae_unsigned = hae_varint & 0xFFFFFFFF;
					packet.altitude_hae = (int32_t)hae_unsigned;
				}
				break;
			
			case 10: // altitude_geoidal_separation (sint32 varint) - in meters
				if (wire_type == 0) // Varint
				{
					uint64_t sep_varint = decodeVarint(data, offset);
					uint32_t sep_unsigned = sep_varint & 0xFFFFFFFF;
					packet.altitude_geoidal_separation = (int32_t)sep_unsigned;
				}
				break;
			
			case 11: // PDOP (uint32 varint) - Position Dilution of Precision, in 1/100 units
				if (wire_type == 0) // Varint
				{
					uint32_t pdop_raw = decodeVarint(data, offset);
					packet.pdop = pdop_raw / 100.0; // Convert from 1/100 units
				}
				break;
			
			case 12: // HDOP (uint32 varint) - Horizontal DOP, in 1/100 units
				if (wire_type == 0) // Varint
				{
					uint32_t hdop_raw = decodeVarint(data, offset);
					packet.hdop = hdop_raw / 100.0; // Convert from 1/100 units
				}
				break;
			
			case 13: // VDOP (uint32 varint) - Vertical DOP, in 1/100 units
				if (wire_type == 0) // Varint
				{
					uint32_t vdop_raw = decodeVarint(data, offset);
					packet.vdop = vdop_raw / 100.0; // Convert from 1/100 units
				}
				break;
			
			case 14: // gps_accuracy (uint32 varint) - GPS accuracy in mm
				if (wire_type == 0) // Varint
				{
					packet.gps_accuracy = decodeVarint(data, offset);
				}
				break;
			
			case 15: // ground_speed (uint32 varint) - ground speed in m/s
				if (wire_type == 0) // Varint
				{
					packet.ground_speed = decodeVarint(data, offset);
				}
				break;
			
			case 16: // ground_track (uint32 varint) - ground track in 1/100 degrees
				if (wire_type == 0) // Varint
				{
					uint32_t track_raw = decodeVarint(data, offset);
					double track_degrees = track_raw / 100.0; // Convert from 1/100 degrees to degrees
					// Validate: ground_track should be in range 0-360 degrees
					// If the value seems reasonable (0-36000 in 1/100 units), use it
					if (track_raw <= 36000)
					{
						packet.ground_track = track_degrees;
					}
					// Otherwise, the field might contain invalid data or be used for something else
				}
				break;
			
			case 17: // fix_quality (uint32 varint) - GPS fix quality
				if (wire_type == 0) // Varint
				{
					packet.fix_quality = decodeVarint(data, offset);
				}
				break;
			
			case 18: // fix_type (uint32 varint) - GPS fix type 2D/3D
				if (wire_type == 0) // Varint
				{
					packet.fix_type = decodeVarint(data, offset);
				}
				break;
			
			case 19: // sats_in_view (uint32 varint) - satellites in view
				if (wire_type == 0) // Varint
				{
					packet.sats_in_view = decodeVarint(data, offset);
				}
				break;
			
			case 20: // sensor_id (uint32 varint) - Sensor ID
				if (wire_type == 0) // Varint
				{
					packet.sensor_id = decodeVarint(data, offset);
				}
				break;
			
			case 21: // next_update (uint32 varint) - seconds until next update
				if (wire_type == 0) // Varint
				{
					packet.next_update = decodeVarint(data, offset);
				}
				break;
			
			case 22: // seq_number (uint32 varint) - sequence number
				if (wire_type == 0) // Varint
				{
					packet.seq_number = decodeVarint(data, offset);
				}
				break;
			
			case 23: // precision_bits (uint32 varint) - bits of precision
				// Note: Some packets may use this field for sats_in_use,
				// but according to protobuf it's precision_bits
				if (wire_type == 0) // Varint
				{
					uint32_t val = decodeVarint(data, offset);
					// If value is reasonable for precision_bits (typically 0-32), use as precision_bits
					// If value is large (like 32), it might be sats_in_use, but we'll use it as precision_bits
					packet.precision_bits = val;
					// If it looks like a satellite count (reasonable range), also set sats_in_use
					if (val > 0 && val <= 50)
					{
						packet.sats_in_use = val;
					}
				}
				break;
			
			default:
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
					offset++;
				}
				break;
		}
	}
	
	return true;
}

bool MeshtasticDecoder::decodeTextMessage(
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

bool MeshtasticDecoder::decodeNodeInfo(
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

bool MeshtasticDecoder::decodeTelemetry(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Parse Telemetry protobuf message according to Meshtastic telemetry.proto
	// Telemetry message structure:
	// - field 1: time (fixed32)
	// - oneof variant (fields 2-8):
	//   - field 2: DeviceMetrics (device_metrics)
	//   - field 3: EnvironmentMetrics (environment_metrics)
	//   - field 4: AirQualityMetrics (air_quality_metrics)
	//   - field 5: PowerMetrics (power_metrics)
	//   - field 6: LocalStats (local_stats)
	//   - field 7: HealthMetrics (health_metrics)
	//   - field 8: HostMetrics (host_metrics)

	if (data.empty())
	{
		return false;
	}

	// Store raw hex data for debugging
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (uint8_t byte : data)
	{
		ss << std::setw(2) << static_cast<int>(byte) << " ";
	}
	packet.raw_telemetry_hex = ss.str();

	size_t offset = 0;
	
	// Parse Telemetry message fields
	while (offset < data.size())
	{
		if (offset >= data.size())
			break;
		
		// Read field tag and wire type
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // time (fixed32)
				if (wire_type == 5) // Fixed32
				{
					if (offset + 4 <= data.size())
					{
						packet.telemetry_time = data[offset] |
												(data[offset + 1] << 8) |
												(data[offset + 2] << 16) |
												(data[offset + 3] << 24);
						offset += 4;
					}
				}
				break;
			
			case 2: // DeviceMetrics (length-delimited)
				if (wire_type == 2)
				{
					packet.telemetry_type = "device_metrics";
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						std::vector<uint8_t> metrics_data(data.begin() + offset,
														 data.begin() + offset + field_length);
						decodeDeviceMetrics(metrics_data, packet);
						offset += field_length;
					}
				}
				break;
			
			case 3: // EnvironmentMetrics (length-delimited)
				if (wire_type == 2)
				{
					packet.telemetry_type = "environment_metrics";
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						std::vector<uint8_t> metrics_data(data.begin() + offset,
														 data.begin() + offset + field_length);
						decodeEnvironmentMetrics(metrics_data, packet);
						offset += field_length;
					}
				}
				break;
			
			case 4: // AirQualityMetrics (length-delimited)
				if (wire_type == 2)
				{
					packet.telemetry_type = "air_quality_metrics";
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						std::vector<uint8_t> metrics_data(data.begin() + offset,
														 data.begin() + offset + field_length);
						decodeAirQualityMetrics(metrics_data, packet);
						offset += field_length;
					}
				}
				break;
			
			case 5: // PowerMetrics (length-delimited)
				if (wire_type == 2)
				{
					packet.telemetry_type = "power_metrics";
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						std::vector<uint8_t> metrics_data(data.begin() + offset,
														 data.begin() + offset + field_length);
						decodePowerMetrics(metrics_data, packet);
						offset += field_length;
					}
				}
				break;
			
			case 6: // LocalStats (length-delimited)
				if (wire_type == 2)
				{
					packet.telemetry_type = "local_stats";
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						std::vector<uint8_t> metrics_data(data.begin() + offset,
														 data.begin() + offset + field_length);
						decodeLocalStats(metrics_data, packet);
						offset += field_length;
					}
				}
				break;
			
			case 7: // HealthMetrics (length-delimited)
				if (wire_type == 2)
				{
					packet.telemetry_type = "health_metrics";
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						std::vector<uint8_t> metrics_data(data.begin() + offset,
														 data.begin() + offset + field_length);
						decodeHealthMetrics(metrics_data, packet);
						offset += field_length;
					}
				}
				break;
			
			case 8: // HostMetrics (length-delimited)
				if (wire_type == 2)
				{
					packet.telemetry_type = "host_metrics";
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						std::vector<uint8_t> metrics_data(data.begin() + offset,
														 data.begin() + offset + field_length);
						decodeHostMetrics(metrics_data, packet);
						offset += field_length;
					}
				}
				break;
			
			default:
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
					offset++;
				}
				break;
		}
	}
	
	// Build telemetry info string
	std::stringstream info_ss;
	info_ss << "Telemetry (" << packet.telemetry_type << ")";
	if (packet.telemetry_time > 0)
	{
		info_ss << " - Time: " << packet.telemetry_time;
	}
	packet.telemetry_info = info_ss.str();

	return true;
}

void MeshtasticDecoder::decodeDeviceMetrics(const std::vector<uint8_t>& data,
													  DecodedPacket& packet)
{
	size_t offset = 0;
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // battery_level (uint32 varint)
				if (wire_type == 0)
					packet.battery_level = decodeVarint(data, offset);
				break;
			case 2: // voltage (float)
				if (wire_type == 5)
					packet.voltage = decodeFloat(data, offset);
				break;
			case 3: // channel_utilization (float)
				if (wire_type == 5)
					packet.channel_utilization = decodeFloat(data, offset);
				break;
			case 4: // air_util_tx (float)
				if (wire_type == 5)
					packet.air_util_tx = decodeFloat(data, offset);
				break;
			case 5: // uptime_seconds (uint32 varint)
				if (wire_type == 0)
					packet.uptime_seconds = decodeVarint(data, offset);
				break;
			default:
				if (wire_type == 0)
					decodeVarint(data, offset);
				else if (wire_type == 5)
					offset += 4;
				else if (wire_type == 2)
				{
					uint64_t len = decodeVarint(data, offset);
					offset += len;
				}
				else
					offset++;
				break;
		}
	}
}

void MeshtasticDecoder::decodeEnvironmentMetrics(const std::vector<uint8_t>& data,
															DecodedPacket& packet)
{
	size_t offset = 0;
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // temperature (float)
				if (wire_type == 5)
					packet.temperature = decodeFloat(data, offset);
				break;
			case 2: // relative_humidity (float)
				if (wire_type == 5)
					packet.relative_humidity = decodeFloat(data, offset);
				break;
			case 3: // barometric_pressure (float)
				if (wire_type == 5)
					packet.barometric_pressure = decodeFloat(data, offset);
				break;
			case 4: // gas_resistance (float)
				if (wire_type == 5)
					packet.gas_resistance = decodeFloat(data, offset);
				break;
			case 5: // voltage (float)
				if (wire_type == 5)
					packet.voltage = decodeFloat(data, offset);
				break;
			case 6: // current (float)
				if (wire_type == 5)
					packet.current = decodeFloat(data, offset);
				break;
			case 7: // iaq (uint32 varint)
				if (wire_type == 0)
					packet.iaq = decodeVarint(data, offset);
				break;
			case 8: // distance (float)
				if (wire_type == 5)
					packet.distance = decodeFloat(data, offset);
				break;
			case 9: // lux (float)
				if (wire_type == 5)
					packet.lux = decodeFloat(data, offset);
				break;
			case 10: // white_lux (float)
				if (wire_type == 5)
					packet.white_lux = decodeFloat(data, offset);
				break;
			case 11: // ir_lux (float)
				if (wire_type == 5)
					packet.ir_lux = decodeFloat(data, offset);
				break;
			case 12: // uv_lux (float)
				if (wire_type == 5)
					packet.uv_lux = decodeFloat(data, offset);
				break;
			case 13: // wind_direction (uint32 varint)
				if (wire_type == 0)
					packet.wind_direction = decodeVarint(data, offset);
				break;
			case 14: // wind_speed (float)
				if (wire_type == 5)
					packet.wind_speed = decodeFloat(data, offset);
				break;
			case 15: // weight (float)
				if (wire_type == 5)
					packet.weight = decodeFloat(data, offset);
				break;
			case 16: // wind_gust (float)
				if (wire_type == 5)
					packet.wind_gust = decodeFloat(data, offset);
				break;
			case 17: // wind_lull (float)
				if (wire_type == 5)
					packet.wind_lull = decodeFloat(data, offset);
				break;
			case 18: // radiation (float)
				if (wire_type == 5)
					packet.radiation = decodeFloat(data, offset);
				break;
			case 19: // rainfall_1h (float)
				if (wire_type == 5)
					packet.rainfall_1h = decodeFloat(data, offset);
				break;
			case 20: // rainfall_24h (float)
				if (wire_type == 5)
					packet.rainfall_24h = decodeFloat(data, offset);
				break;
			case 21: // soil_moisture (uint32 varint)
				if (wire_type == 0)
					packet.soil_moisture = decodeVarint(data, offset);
				break;
			case 22: // soil_temperature (float)
				if (wire_type == 5)
					packet.soil_temperature = decodeFloat(data, offset);
				break;
			default:
				if (wire_type == 0)
					decodeVarint(data, offset);
				else if (wire_type == 5)
					offset += 4;
				else if (wire_type == 2)
				{
					uint64_t len = decodeVarint(data, offset);
					offset += len;
				}
				else
					offset++;
				break;
		}
	}
}

void MeshtasticDecoder::decodeAirQualityMetrics(const std::vector<uint8_t>& data,
														   DecodedPacket& packet)
{
	size_t offset = 0;
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // pm10_standard (uint32 varint)
				if (wire_type == 0)
					packet.pm10_standard = decodeVarint(data, offset);
				break;
			case 2: // pm25_standard (uint32 varint)
				if (wire_type == 0)
					packet.pm25_standard = decodeVarint(data, offset);
				break;
			case 3: // pm100_standard (uint32 varint)
				if (wire_type == 0)
					packet.pm100_standard = decodeVarint(data, offset);
				break;
			case 4: // pm10_environmental (uint32 varint)
				if (wire_type == 0)
					packet.pm10_environmental = decodeVarint(data, offset);
				break;
			case 5: // pm25_environmental (uint32 varint)
				if (wire_type == 0)
					packet.pm25_environmental = decodeVarint(data, offset);
				break;
			case 6: // pm100_environmental (uint32 varint)
				if (wire_type == 0)
					packet.pm100_environmental = decodeVarint(data, offset);
				break;
			case 7: // particles_03um (uint32 varint)
				if (wire_type == 0)
					packet.particles_03um = decodeVarint(data, offset);
				break;
			case 8: // particles_05um (uint32 varint)
				if (wire_type == 0)
					packet.particles_05um = decodeVarint(data, offset);
				break;
			case 9: // particles_10um (uint32 varint)
				if (wire_type == 0)
					packet.particles_10um = decodeVarint(data, offset);
				break;
			case 10: // particles_25um (uint32 varint)
				if (wire_type == 0)
					packet.particles_25um = decodeVarint(data, offset);
				break;
			case 11: // particles_50um (uint32 varint)
				if (wire_type == 0)
					packet.particles_50um = decodeVarint(data, offset);
				break;
			case 12: // particles_100um (uint32 varint)
				if (wire_type == 0)
					packet.particles_100um = decodeVarint(data, offset);
				break;
			case 13: // co2 (uint32 varint)
				if (wire_type == 0)
					packet.co2 = decodeVarint(data, offset);
				break;
			case 14: // co2_temperature (float)
				if (wire_type == 5)
					packet.co2_temperature = decodeFloat(data, offset);
				break;
			case 15: // co2_humidity (float)
				if (wire_type == 5)
					packet.co2_humidity = decodeFloat(data, offset);
				break;
			case 16: // form_formaldehyde (float)
				if (wire_type == 5)
					packet.form_formaldehyde = decodeFloat(data, offset);
				break;
			case 17: // form_humidity (float)
				if (wire_type == 5)
					packet.form_humidity = decodeFloat(data, offset);
				break;
			case 18: // form_temperature (float)
				if (wire_type == 5)
					packet.form_temperature = decodeFloat(data, offset);
				break;
			default:
				if (wire_type == 0)
					decodeVarint(data, offset);
				else if (wire_type == 5)
					offset += 4;
				else if (wire_type == 2)
				{
					uint64_t len = decodeVarint(data, offset);
					offset += len;
				}
				else
					offset++;
				break;
		}
	}
}

void MeshtasticDecoder::decodePowerMetrics(const std::vector<uint8_t>& data,
													  DecodedPacket& packet)
{
	size_t offset = 0;
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // ch1_voltage (float)
				if (wire_type == 5)
					packet.ch1_voltage = decodeFloat(data, offset);
				break;
			case 2: // ch1_current (float)
				if (wire_type == 5)
					packet.ch1_current = decodeFloat(data, offset);
				break;
			case 3: // ch2_voltage (float)
				if (wire_type == 5)
					packet.ch2_voltage = decodeFloat(data, offset);
				break;
			case 4: // ch2_current (float)
				if (wire_type == 5)
					packet.ch2_current = decodeFloat(data, offset);
				break;
			case 5: // ch3_voltage (float)
				if (wire_type == 5)
					packet.ch3_voltage = decodeFloat(data, offset);
				break;
			case 6: // ch3_current (float)
				if (wire_type == 5)
					packet.ch3_current = decodeFloat(data, offset);
				break;
			case 7: // ch4_voltage (float)
				if (wire_type == 5)
					packet.ch4_voltage = decodeFloat(data, offset);
				break;
			case 8: // ch4_current (float)
				if (wire_type == 5)
					packet.ch4_current = decodeFloat(data, offset);
				break;
			case 9: // ch5_voltage (float)
				if (wire_type == 5)
					packet.ch5_voltage = decodeFloat(data, offset);
				break;
			case 10: // ch5_current (float)
				if (wire_type == 5)
					packet.ch5_current = decodeFloat(data, offset);
				break;
			case 11: // ch6_voltage (float)
				if (wire_type == 5)
					packet.ch6_voltage = decodeFloat(data, offset);
				break;
			case 12: // ch6_current (float)
				if (wire_type == 5)
					packet.ch6_current = decodeFloat(data, offset);
				break;
			case 13: // ch7_voltage (float)
				if (wire_type == 5)
					packet.ch7_voltage = decodeFloat(data, offset);
				break;
			case 14: // ch7_current (float)
				if (wire_type == 5)
					packet.ch7_current = decodeFloat(data, offset);
				break;
			case 15: // ch8_voltage (float)
				if (wire_type == 5)
					packet.ch8_voltage = decodeFloat(data, offset);
				break;
			case 16: // ch8_current (float)
				if (wire_type == 5)
					packet.ch8_current = decodeFloat(data, offset);
				break;
			default:
				if (wire_type == 0)
					decodeVarint(data, offset);
				else if (wire_type == 5)
					offset += 4;
				else if (wire_type == 2)
				{
					uint64_t len = decodeVarint(data, offset);
					offset += len;
				}
				else
					offset++;
				break;
		}
	}
}

void MeshtasticDecoder::decodeLocalStats(const std::vector<uint8_t>& data,
													DecodedPacket& packet)
{
	size_t offset = 0;
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // uptime_seconds (uint32 varint)
				if (wire_type == 0)
					packet.uptime_seconds = decodeVarint(data, offset);
				break;
			case 2: // channel_utilization (float)
				if (wire_type == 5)
					packet.channel_utilization = decodeFloat(data, offset);
				break;
			case 3: // air_util_tx (float)
				if (wire_type == 5)
					packet.air_util_tx = decodeFloat(data, offset);
				break;
			case 4: // num_packets_tx (uint32 varint)
				if (wire_type == 0)
					packet.num_packets_tx = decodeVarint(data, offset);
				break;
			case 5: // num_packets_rx (uint32 varint)
				if (wire_type == 0)
					packet.num_packets_rx = decodeVarint(data, offset);
				break;
			case 6: // num_packets_rx_bad (uint32 varint)
				if (wire_type == 0)
					packet.num_packets_rx_bad = decodeVarint(data, offset);
				break;
			case 7: // num_online_nodes (uint32 varint)
				if (wire_type == 0)
					packet.num_online_nodes = decodeVarint(data, offset);
				break;
			case 8: // num_total_nodes (uint32 varint)
				if (wire_type == 0)
					packet.num_total_nodes = decodeVarint(data, offset);
				break;
			case 9: // num_rx_dupe (uint32 varint)
				if (wire_type == 0)
					packet.num_rx_dupe = decodeVarint(data, offset);
				break;
			case 10: // num_tx_relay (uint32 varint)
				if (wire_type == 0)
					packet.num_tx_relay = decodeVarint(data, offset);
				break;
			case 11: // num_tx_relay_canceled (uint32 varint)
				if (wire_type == 0)
					packet.num_tx_relay_canceled = decodeVarint(data, offset);
				break;
			case 12: // heap_total_bytes (uint32 varint)
				if (wire_type == 0)
					packet.heap_total_bytes = decodeVarint(data, offset);
				break;
			case 13: // heap_free_bytes (uint32 varint)
				if (wire_type == 0)
					packet.heap_free_bytes = decodeVarint(data, offset);
				break;
			case 14: // num_tx_dropped (uint32 varint)
				if (wire_type == 0)
					packet.num_tx_dropped = decodeVarint(data, offset);
				break;
			default:
				if (wire_type == 0)
					decodeVarint(data, offset);
				else if (wire_type == 5)
					offset += 4;
				else if (wire_type == 2)
				{
					uint64_t len = decodeVarint(data, offset);
					offset += len;
				}
				else
					offset++;
				break;
		}
	}
}

void MeshtasticDecoder::decodeHealthMetrics(const std::vector<uint8_t>& data,
													   DecodedPacket& packet)
{
	size_t offset = 0;
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // heart_bpm (uint32 varint)
				if (wire_type == 0)
					packet.heart_bpm = decodeVarint(data, offset);
				break;
			case 2: // spO2 (uint32 varint)
				if (wire_type == 0)
					packet.spO2 = decodeVarint(data, offset);
				break;
			case 3: // body_temperature (float)
				if (wire_type == 5)
					packet.body_temperature = decodeFloat(data, offset);
				break;
			default:
				if (wire_type == 0)
					decodeVarint(data, offset);
				else if (wire_type == 5)
					offset += 4;
				else if (wire_type == 2)
				{
					uint64_t len = decodeVarint(data, offset);
					offset += len;
				}
				else
					offset++;
				break;
		}
	}
}

void MeshtasticDecoder::decodeHostMetrics(const std::vector<uint8_t>& data,
													 DecodedPacket& packet)
{
	size_t offset = 0;
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // uptime_seconds (uint32 varint)
				if (wire_type == 0)
					packet.uptime_seconds = decodeVarint(data, offset);
				break;
			case 2: // freemem_bytes (uint64 varint)
				if (wire_type == 0)
					packet.freemem_bytes = decodeVarint(data, offset);
				break;
			case 3: // diskfree1_bytes (uint64 varint)
				if (wire_type == 0)
					packet.diskfree1_bytes = decodeVarint(data, offset);
				break;
			case 4: // diskfree2_bytes (uint64 varint)
				if (wire_type == 0)
					packet.diskfree2_bytes = decodeVarint(data, offset);
				break;
			case 5: // diskfree3_bytes (uint64 varint)
				if (wire_type == 0)
					packet.diskfree3_bytes = decodeVarint(data, offset);
				break;
			case 6: // load1 (uint32 varint)
				if (wire_type == 0)
					packet.load1 = decodeVarint(data, offset);
				break;
			case 7: // load5 (uint32 varint)
				if (wire_type == 0)
					packet.load5 = decodeVarint(data, offset);
				break;
			case 8: // load15 (uint32 varint)
				if (wire_type == 0)
					packet.load15 = decodeVarint(data, offset);
				break;
			case 9: // host_user_string (string)
				if (wire_type == 2)
				{
					uint64_t len = decodeVarint(data, offset);
					if (len > 0 && offset + len <= data.size())
					{
						packet.host_user_string = std::string(data.begin() + offset,
															  data.begin() + offset + len);
						offset += len;
					}
				}
				break;
			default:
				if (wire_type == 0)
					decodeVarint(data, offset);
				else if (wire_type == 5)
					offset += 4;
				else if (wire_type == 2)
				{
					uint64_t len = decodeVarint(data, offset);
					offset += len;
				}
				else
					offset++;
				break;
		}
	}
}

bool MeshtasticDecoder::decodeTraceroute(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Parse Routing protobuf message according to Meshtastic mesh.proto specification
	// Routing message structure:
	// - oneof variant:
	//   - field 1: RouteDiscovery route_request (length-delimited)
	//   - field 2: RouteDiscovery route_reply (length-delimited)
	//   - field 3: Error error_reason (varint)
	//
	// RouteDiscovery message fields:
	// - field 1: repeated fixed32 route
	// - field 2: repeated int32 snr_towards
	// - field 3: repeated fixed32 route_back
	// - field 4: repeated int32 snr_back
	
	if (data.empty())
	{
		return false;
	}
	
	size_t offset = 0;
	
	// First, decode the Routing message to get the RouteDiscovery
	// Note: Both field 1 (route_request) and field 2 (route_reply) are RouteDiscovery messages
	// They may contain different parts (route nodes vs SNR values), so we need to merge them
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		if (field_number == 1 && wire_type == 2)
		{
			// Field 1: RouteDiscovery route_request (length-delimited)
			packet.route_type = "route_request";
			uint64_t field_length = decodeVarint(data, offset);
			if (field_length > 0 && offset + field_length <= data.size())
			{
				std::vector<uint8_t> route_discovery_data(data.begin() + offset,
														 data.begin() + offset + field_length);
				decodeRouteDiscovery(route_discovery_data, packet);
				offset += field_length;
			}
		}
		else if (field_number == 2 && wire_type == 2)
		{
			// Field 2: RouteDiscovery route_reply (length-delimited)
			// This may contain route nodes, SNR values, or both
			if (packet.route_type.empty())
			{
				packet.route_type = "route_reply";
			}
			uint64_t field_length = decodeVarint(data, offset);
			if (field_length > 0 && offset + field_length <= data.size())
			{
				std::vector<uint8_t> route_discovery_data(data.begin() + offset,
														 data.begin() + offset + field_length);
				// Decode this RouteDiscovery message and merge with existing data
				decodeRouteDiscovery(route_discovery_data, packet);
				offset += field_length;
			}
		}
		else if (field_number == 3 && wire_type == 0)
		{
			// Field 3: Error error_reason (varint)
			// Decode and skip for now (could store error code if needed)
			decodeVarint(data, offset);
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
				offset++;
			}
		}
	}
	
	// Format route paths
	formatRoutePath(packet.route_nodes, packet.route_path);
	formatRoutePath(packet.route_back_nodes, packet.route_back_path);
	
	packet.route_count = packet.route_nodes.size();
	packet.route_back_count = packet.route_back_nodes.size();
	
	return true;
}

void MeshtasticDecoder::decodeRouteDiscovery(
  const std::vector<uint8_t>& data,
  DecodedPacket& packet)
{
	// Parse RouteDiscovery protobuf message according to Meshtastic mesh.proto
	// RouteDiscovery message fields:
	// - field 1: repeated fixed32 route
	// - field 2: repeated int32 snr_towards
	// - field 3: repeated fixed32 route_back
	// - field 4: repeated int32 snr_back
	//
	// Note: In some cases, the RouteDiscovery message may contain just packed
	// fixed32 values without field tags (non-standard but used by Meshtastic)
	
	if (data.empty())
	{
		return;
	}
	
	size_t offset = 0;
	
	// Check if the data starts with a valid field tag
	// If not, it might be packed values directly (non-standard encoding)
	if (offset < data.size())
	{
		uint8_t first_byte = data[offset];
		uint8_t first_field = first_byte >> 3;
		uint8_t first_wire_type = first_byte & 0x07;
		
		// If the first byte doesn't look like a valid field tag for RouteDiscovery,
		// try parsing as packed values
		if (first_field > 4 || first_wire_type > 5)
		{
			// Check if it's packed fixed32 route values (size is multiple of 4)
			if (data.size() % 4 == 0)
			{
				// Likely packed fixed32 route values without field tag
				for (size_t i = 0; i < data.size(); i += 4)
				{
					if (i + 4 <= data.size())
					{
						uint32_t node_id = data[i] |
										   (data[i + 1] << 8) |
										   (data[i + 2] << 16) |
										   (data[i + 3] << 24);
						packet.route_nodes.push_back(node_id);
					}
				}
				return;
			}
			else
			{
				// Might be packed int32 varints for SNR values
				// Try parsing as packed varints
				size_t snr_offset = 0;
				while (snr_offset < data.size())
				{
					uint64_t snr_val = decodeVarint(data, snr_offset);
					// Convert to signed int32 using two's complement
					// Protobuf int32 uses two's complement encoding
					uint32_t val_32 = snr_val & 0xFFFFFFFF;
					int32_t snr_signed;
					if (val_32 & 0x80000000)
					{
						snr_signed = (int32_t)(val_32 - 0x100000000);
					}
					else
					{
						snr_signed = (int32_t)val_32;
					}
					packet.snr_towards.push_back(snr_signed);
					
					// Safety check to avoid infinite loop
					if (snr_offset >= data.size())
						break;
				}
				return;
			}
		}
	}
	
	while (offset < data.size())
	{
		uint64_t tag_wire_type = decodeVarint(data, offset);
		if (tag_wire_type == 0)
			break;
		
		uint8_t field_number = tag_wire_type >> 3;
		uint8_t wire_type = tag_wire_type & 0x07;
		
		switch (field_number)
		{
			case 1: // repeated fixed32 route
				if (wire_type == 5) // Fixed32
				{
					// Repeated fixed32 fields are not packed in protobuf
					// Each value appears with its field tag
					if (offset + 4 <= data.size())
					{
						uint32_t node_id = data[offset] |
										   (data[offset + 1] << 8) |
										   (data[offset + 2] << 16) |
										   (data[offset + 3] << 24);
						packet.route_nodes.push_back(node_id);
						offset += 4;
					}
				}
				else if (wire_type == 2)
				{
					// Length-delimited (packed repeated fixed32)
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size() && field_length % 4 == 0)
					{
						// Parse packed fixed32 values
						for (size_t i = 0; i < field_length; i += 4)
						{
							uint32_t node_id = data[offset + i] |
											   (data[offset + i + 1] << 8) |
											   (data[offset + i + 2] << 16) |
											   (data[offset + i + 3] << 24);
							packet.route_nodes.push_back(node_id);
						}
						offset += field_length;
					}
				}
				break;
			
			case 2: // repeated int32 snr_towards
				if (wire_type == 0) // Varint
				{
					// Repeated varint fields are not packed
					// Each value appears with its field tag
					uint64_t snr_val = decodeVarint(data, offset);
					// Convert to signed int32
					int32_t snr_signed = (int32_t)(snr_val & 0xFFFFFFFF);
					packet.snr_towards.push_back(snr_signed);
				}
				else if (wire_type == 2)
				{
					// Length-delimited (packed repeated varint)
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						size_t packed_offset = offset;
						while (packed_offset < offset + field_length)
						{
							uint64_t snr_val = decodeVarint(data, packed_offset);
							int32_t snr_signed = (int32_t)(snr_val & 0xFFFFFFFF);
							packet.snr_towards.push_back(snr_signed);
						}
						offset += field_length;
					}
				}
				break;
			
			case 3: // repeated fixed32 route_back
				if (wire_type == 5) // Fixed32
				{
					if (offset + 4 <= data.size())
					{
						uint32_t node_id = data[offset] |
										   (data[offset + 1] << 8) |
										   (data[offset + 2] << 16) |
										   (data[offset + 3] << 24);
						packet.route_back_nodes.push_back(node_id);
						offset += 4;
					}
				}
				else if (wire_type == 2)
				{
					// Length-delimited (packed repeated fixed32)
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size() && field_length % 4 == 0)
					{
						for (size_t i = 0; i < field_length; i += 4)
						{
							uint32_t node_id = data[offset + i] |
											   (data[offset + i + 1] << 8) |
											   (data[offset + i + 2] << 16) |
											   (data[offset + i + 3] << 24);
							packet.route_back_nodes.push_back(node_id);
						}
						offset += field_length;
					}
				}
				break;
			
			case 4: // repeated int32 snr_back
				if (wire_type == 0) // Varint
				{
					uint64_t snr_val = decodeVarint(data, offset);
					int32_t snr_signed = (int32_t)(snr_val & 0xFFFFFFFF);
					packet.snr_back.push_back(snr_signed);
				}
				else if (wire_type == 2)
				{
					// Length-delimited (packed repeated varint)
					uint64_t field_length = decodeVarint(data, offset);
					if (field_length > 0 && offset + field_length <= data.size())
					{
						size_t packed_offset = offset;
						while (packed_offset < offset + field_length)
						{
							uint64_t snr_val = decodeVarint(data, packed_offset);
							int32_t snr_signed = (int32_t)(snr_val & 0xFFFFFFFF);
							packet.snr_back.push_back(snr_signed);
						}
						offset += field_length;
					}
				}
				break;
			
			default:
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
					offset++;
				}
				break;
		}
	}
}

void MeshtasticDecoder::formatRoutePath(
  const std::vector<uint32_t>& nodes,
  std::string& path)
{
	if (nodes.empty())
	{
		path = "";
		return;
	}
	
	std::stringstream route_path_ss;
	for (size_t i = 0; i < nodes.size(); ++i)
	{
		if (i > 0)
			route_path_ss << " → ";
		
		// Format node ID as hex string
		std::stringstream node_ss;
		node_ss << "!" << std::hex << std::setfill('0') << std::setw(8) << nodes[i];
		route_path_ss << node_ss.str();
	}
	path = route_path_ss.str();
}

uint64_t MeshtasticDecoder::decodeVarint(
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

float MeshtasticDecoder::decodeFloat(const std::vector<uint8_t>& data,
											   size_t& offset)
{
	if (offset + 4 > data.size())
	{
		return 0.0f;
	}
	
	// Float is stored as 32-bit little-endian IEEE 754
	uint32_t bits = data[offset] |
					(data[offset + 1] << 8) |
					(data[offset + 2] << 16) |
					(data[offset + 3] << 24);
	offset += 4;
	
	// Reinterpret bits as float
	float result;
	memcpy(&result, &bits, sizeof(float));
	return result;
}

uint64_t MeshtasticDecoder::decodeUint64(const std::vector<uint8_t>& data,
													size_t& offset)
{
	if (offset + 8 > data.size())
	{
		return 0;
	}
	
	uint64_t result = (uint64_t)data[offset] |
					  ((uint64_t)data[offset + 1] << 8) |
					  ((uint64_t)data[offset + 2] << 16) |
					  ((uint64_t)data[offset + 3] << 24) |
					  ((uint64_t)data[offset + 4] << 32) |
					  ((uint64_t)data[offset + 5] << 40) |
					  ((uint64_t)data[offset + 6] << 48) |
					  ((uint64_t)data[offset + 7] << 56);
	offset += 8;
	return result;
}

void MeshtasticDecoder::calculateSkipAndRouting(DecodedPacket& packet)
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

std::string MeshtasticDecoder::toJson(const DecodedPacket& packet)
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
			json << "    \"altitude\": " << packet.altitude;
			
			// Build list of optional fields to include
			if (packet.timestamp > 0)
			{
				json << ",\n    \"timestamp\": " << packet.timestamp;
			}
			
			if (packet.sats_in_view > 0)
			{
				json << ",\n    \"sats_in_view\": " << packet.sats_in_view;
			}
			
			if (packet.sats_in_use > 0)
			{
				json << ",\n    \"sats_in_use\": " << packet.sats_in_use;
			}
			
			if (packet.ground_speed > 0)
			{
				json << ",\n    \"ground_speed\": " << packet.ground_speed << ",\n    \"ground_speed_unit\": \"m/s\"";
			}
			
			if (packet.ground_track >= 0.0 && packet.ground_track <= 360.0)
			{
				json << ",\n    \"ground_track\": " << formatDouble(packet.ground_track) << ",\n    \"ground_track_unit\": \"degrees\"";
			}
			
			if (packet.gps_accuracy > 0)
			{
				json << ",\n    \"gps_accuracy\": " << packet.gps_accuracy << ",\n    \"gps_accuracy_unit\": \"mm\"";
			}
			
			if (packet.pdop > 0.0)
			{
				json << ",\n    \"pdop\": " << formatDouble(packet.pdop);
			}
			
			if (packet.hdop > 0.0)
			{
				json << ",\n    \"hdop\": " << formatDouble(packet.hdop);
			}
			
			if (packet.vdop > 0.0)
			{
				json << ",\n    \"vdop\": " << formatDouble(packet.vdop);
			}
			
			if (packet.fix_quality > 0)
			{
				json << ",\n    \"fix_quality\": " << packet.fix_quality;
			}
			
			if (packet.fix_type > 0)
			{
				json << ",\n    \"fix_type\": " << packet.fix_type;
			}
			
			if (packet.precision_bits > 0)
			{
				json << ",\n    \"precision_bits\": " << packet.precision_bits;
			}
			
			if (packet.altitude_hae != 0)
			{
				json << ",\n    \"altitude_hae\": " << packet.altitude_hae << ",\n    \"altitude_hae_unit\": \"meters\"";
			}
			
			if (packet.altitude_geoidal_separation != 0)
			{
				json << ",\n    \"altitude_geoidal_separation\": " << packet.altitude_geoidal_separation << ",\n    \"altitude_geoidal_separation_unit\": \"meters\"";
			}
			
			// LocationSource enum: 0=LOC_UNSET, 1=LOC_MANUAL, 2=LOC_INTERNAL, 3=LOC_EXTERNAL
			// Values >= 4 are unknown (protobuf forward compatibility - future enum values)
			// Note: Value 0 (UNSET) is the default and typically not shown when unset
			if (packet.location_source > 0)
			{
				const char* loc_sources[] = {"UNSET", "MANUAL", "INTERNAL", "EXTERNAL"};
				json << ",\n    \"location_source\": " << packet.location_source;
				if (packet.location_source < 4)
				{
					json << ",\n    \"location_source_name\": \"" << loc_sources[packet.location_source] << "\"";
				}
				else
				{
					// Unknown enum value (>= 4) - could be a future Meshtastic enum value
					// or corrupted data. Protobuf preserves unknown enum values for forward compatibility.
					json << ",\n    \"location_source_name\": \"UNKNOWN\"";
				}
			}
			
			// AltitudeSource enum: 0=ALT_UNSET, 1=ALT_MANUAL, 2=ALT_INTERNAL, 3=ALT_EXTERNAL, 4=ALT_BAROMETRIC
			// Values >= 5 are unknown (protobuf forward compatibility - future enum values)
			// Note: Value 0 (UNSET) is the default and typically not shown when unset
			if (packet.altitude_source > 0)
			{
				const char* alt_sources[] = {"UNSET", "MANUAL", "INTERNAL", "EXTERNAL", "BAROMETRIC"};
				json << ",\n    \"altitude_source\": " << packet.altitude_source;
				if (packet.altitude_source < 5)
				{
					json << ",\n    \"altitude_source_name\": \"" << alt_sources[packet.altitude_source] << "\"";
				}
				else
				{
					// Unknown enum value (>= 5) - could be a future Meshtastic enum value
					// or corrupted data. Protobuf preserves unknown enum values for forward compatibility.
					json << ",\n    \"altitude_source_name\": \"UNKNOWN\"";
				}
			}
			
			if (packet.timestamp_millis_adjust != 0)
			{
				json << ",\n    \"timestamp_millis_adjust\": " << packet.timestamp_millis_adjust;
			}
			
			if (packet.sensor_id > 0)
			{
				json << ",\n    \"sensor_id\": " << packet.sensor_id;
			}
			
			if (packet.next_update > 0)
			{
				json << ",\n    \"next_update\": " << packet.next_update << ",\n    \"next_update_unit\": \"seconds\"";
			}
			
			if (packet.seq_number > 0)
			{
				json << ",\n    \"seq_number\": " << packet.seq_number;
			}
			
			json << "\n  },\n";
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
			json << "    \"type\": \"" << escapeJsonString(packet.telemetry_type) << "\",\n";
			if (packet.telemetry_time > 0)
			{
				json << "    \"time\": " << packet.telemetry_time << ",\n";
			}
			
			if (packet.telemetry_type == "device_metrics")
			{
				bool first = true;
				// Always include battery_level (can be 0-100, or >100 for powered)
				if (!first) json << ",\n";
				json << "    \"battery_level\": " << packet.battery_level;
				first = false;
				if (packet.voltage != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"voltage\": " << std::fixed << std::setprecision(2) << packet.voltage;
					first = false;
				}
				if (packet.channel_utilization != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"channel_utilization\": " << std::fixed << std::setprecision(2) << packet.channel_utilization;
					first = false;
				}
				if (packet.air_util_tx != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"air_util_tx\": " << std::fixed << std::setprecision(2) << packet.air_util_tx;
					first = false;
				}
				if (packet.uptime_seconds > 0)
				{
					if (!first) json << ",\n";
					json << "    \"uptime_seconds\": " << packet.uptime_seconds;
					first = false;
				}
			}
			else if (packet.telemetry_type == "environment_metrics")
			{
				bool first = true;
				if (packet.temperature != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"temperature\": " << std::fixed << std::setprecision(2) << packet.temperature;
					first = false;
				}
				if (packet.relative_humidity != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"relative_humidity\": " << std::fixed << std::setprecision(2) << packet.relative_humidity;
					first = false;
				}
				if (packet.barometric_pressure != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"barometric_pressure\": " << std::fixed << std::setprecision(2) << packet.barometric_pressure;
					first = false;
				}
				if (packet.gas_resistance != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"gas_resistance\": " << std::fixed << std::setprecision(2) << packet.gas_resistance;
					first = false;
				}
				if (packet.voltage != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"voltage\": " << std::fixed << std::setprecision(2) << packet.voltage;
					first = false;
				}
				if (packet.current != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"current\": " << std::fixed << std::setprecision(2) << packet.current;
					first = false;
				}
				if (packet.iaq > 0)
				{
					if (!first) json << ",\n";
					json << "    \"iaq\": " << packet.iaq;
					first = false;
				}
				if (packet.distance != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"distance\": " << std::fixed << std::setprecision(2) << packet.distance;
					first = false;
				}
				if (packet.lux != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"lux\": " << std::fixed << std::setprecision(2) << packet.lux;
					first = false;
				}
				if (packet.wind_speed != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"wind_speed\": " << std::fixed << std::setprecision(2) << packet.wind_speed;
					first = false;
				}
				if (packet.wind_direction > 0)
				{
					if (!first) json << ",\n";
					json << "    \"wind_direction\": " << packet.wind_direction;
					first = false;
				}
				if (packet.soil_moisture > 0)
				{
					if (!first) json << ",\n";
					json << "    \"soil_moisture\": " << packet.soil_moisture;
					first = false;
				}
				if (packet.soil_temperature != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"soil_temperature\": " << std::fixed << std::setprecision(2) << packet.soil_temperature;
					first = false;
				}
			}
			else if (packet.telemetry_type == "air_quality_metrics")
			{
				bool first = true;
				if (packet.pm10_standard > 0)
				{
					if (!first) json << ",\n";
					json << "    \"pm10_standard\": " << packet.pm10_standard;
					first = false;
				}
				if (packet.pm25_standard > 0)
				{
					if (!first) json << ",\n";
					json << "    \"pm25_standard\": " << packet.pm25_standard;
					first = false;
				}
				if (packet.pm100_standard > 0)
				{
					if (!first) json << ",\n";
					json << "    \"pm100_standard\": " << packet.pm100_standard;
					first = false;
				}
				if (packet.co2 > 0)
				{
					if (!first) json << ",\n";
					json << "    \"co2\": " << packet.co2;
					first = false;
				}
			}
			else if (packet.telemetry_type == "power_metrics")
			{
				bool first = true;
				if (packet.ch1_voltage != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"ch1_voltage\": " << std::fixed << std::setprecision(2) << packet.ch1_voltage;
					first = false;
				}
				if (packet.ch1_current != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"ch1_current\": " << std::fixed << std::setprecision(2) << packet.ch1_current;
					first = false;
				}
			}
			else if (packet.telemetry_type == "local_stats")
			{
				bool first = true;
				if (packet.uptime_seconds > 0)
				{
					if (!first) json << ",\n";
					json << "    \"uptime_seconds\": " << packet.uptime_seconds;
					first = false;
				}
				if (packet.channel_utilization != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"channel_utilization\": " << std::fixed << std::setprecision(2) << packet.channel_utilization;
					first = false;
				}
				if (packet.num_packets_tx > 0)
				{
					if (!first) json << ",\n";
					json << "    \"num_packets_tx\": " << packet.num_packets_tx;
					first = false;
				}
				if (packet.num_packets_rx > 0)
				{
					if (!first) json << ",\n";
					json << "    \"num_packets_rx\": " << packet.num_packets_rx;
					first = false;
				}
				if (packet.num_online_nodes > 0)
				{
					if (!first) json << ",\n";
					json << "    \"num_online_nodes\": " << packet.num_online_nodes;
					first = false;
				}
			}
			else if (packet.telemetry_type == "health_metrics")
			{
				bool first = true;
				if (packet.heart_bpm > 0)
				{
					if (!first) json << ",\n";
					json << "    \"heart_bpm\": " << packet.heart_bpm;
					first = false;
				}
				if (packet.spO2 > 0)
				{
					if (!first) json << ",\n";
					json << "    \"spO2\": " << packet.spO2;
					first = false;
				}
				if (packet.body_temperature != 0.0f)
				{
					if (!first) json << ",\n";
					json << "    \"body_temperature\": " << std::fixed << std::setprecision(2) << packet.body_temperature;
					first = false;
				}
			}
			else if (packet.telemetry_type == "host_metrics")
			{
				bool first = true;
				if (packet.uptime_seconds > 0)
				{
					if (!first) json << ",\n";
					json << "    \"uptime_seconds\": " << packet.uptime_seconds;
					first = false;
				}
				if (packet.freemem_bytes > 0)
				{
					if (!first) json << ",\n";
					json << "    \"freemem_bytes\": " << packet.freemem_bytes;
					first = false;
				}
				if (packet.diskfree1_bytes > 0)
				{
					if (!first) json << ",\n";
					json << "    \"diskfree1_bytes\": " << packet.diskfree1_bytes;
					first = false;
				}
			}
			
			json << "\n  },\n";
			json << "  \"telemetry_raw_hex\": \"" << escapeJsonString(packet.raw_telemetry_hex) << "\",\n";
		}
		else if (packet.port == 70)
		{ // TRACEROUTE_APP
			json << "  \"traceroute\": {\n";
			if (!packet.route_type.empty())
			{
				json << "    \"route_type\": \"" << escapeJsonString(packet.route_type) << "\",\n";
			}
			json << "    \"route_count\": " << packet.route_count << ",\n";
			if (!packet.route_path.empty())
			{
				json << "    \"route_path\": \"" << escapeJsonString(packet.route_path) << "\",\n";
			}
			json << "    \"route_nodes\": [";
			for (size_t i = 0; i < packet.route_nodes.size(); ++i)
			{
				if (i > 0)
					json << ", ";
				json << "\"0x" << std::hex << std::setfill('0') << std::setw(8) << packet.route_nodes[i] << "\"";
			}
			json << "]";
			
			if (!packet.snr_towards.empty())
			{
				json << ",\n    \"snr_towards\": [";
				for (size_t i = 0; i < packet.snr_towards.size(); ++i)
				{
					if (i > 0)
						json << ", ";
					// SNR values are in dB, scaled by 4 (divide by 4 to get actual dB)
					double snr_dB = packet.snr_towards[i] / 4.0;
					json << std::fixed << std::setprecision(2) << snr_dB;
				}
				json << "],\n    \"snr_towards_unit\": \"dB\"";
			}
			
			if (packet.route_back_count > 0)
			{
				json << ",\n    \"route_back_count\": " << packet.route_back_count;
			}
			if (!packet.route_back_path.empty())
			{
				json << ",\n    \"route_back_path\": \"" << escapeJsonString(packet.route_back_path) << "\"";
			}
			if (!packet.route_back_nodes.empty())
			{
				json << ",\n    \"route_back_nodes\": [";
				for (size_t i = 0; i < packet.route_back_nodes.size(); ++i)
				{
					if (i > 0)
						json << ", ";
					json << "\"0x" << std::hex << std::setfill('0') << std::setw(8) << packet.route_back_nodes[i] << "\"";
				}
				json << "]";
			}
			
			if (!packet.snr_back.empty())
			{
				json << ",\n    \"snr_back\": [";
				for (size_t i = 0; i < packet.snr_back.size(); ++i)
				{
					if (i > 0)
						json << ", ";
					// SNR values are in dB, scaled by 4 (divide by 4 to get actual dB)
					double snr_dB = packet.snr_back[i] / 4.0;
					json << std::fixed << std::setprecision(2) << snr_dB;
				}
				json << "],\n    \"snr_back_unit\": \"dB\"";
			}
			
			json << "\n  },\n";
		}

		json << "  \"decrypted_payload\": \""
			 << escapeJsonString(packet.decrypted_payload_hex) << "\"\n";
	}

	json << "}";

	return json.str();
}

std::vector<uint8_t> MeshtasticDecoder::hexStringToBytes(
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

std::string MeshtasticDecoder::bytesToHexString(
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

std::string MeshtasticDecoder::escapeJsonString(
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

std::string MeshtasticDecoder::formatDouble(double value,
													  int precision)
{
	std::stringstream ss;
	ss << std::fixed << std::setprecision(precision) << value;
	return ss.str();
}
