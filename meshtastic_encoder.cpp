#include "meshtastic_encoder.h"
#include "aes_barebones.h"
#include <cstring>
#include <random>

#ifdef ARDUINO
#include <esp_random.h>
#include <Arduino.h>  // For millis() and analogRead()
#endif

const std::vector<uint8_t> MeshtasticEncoder::DEFAULT_PSK = {
	0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
	0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

// Protobuf encoding utilities

void MeshtasticEncoder::encodeVarint(std::vector<uint8_t>& buffer, uint64_t value)
{
	while (value > 0x7F)
	{
		buffer.push_back((uint8_t)((value & 0x7F) | 0x80));
		value >>= 7;
	}
	buffer.push_back((uint8_t)(value & 0x7F));
}

void MeshtasticEncoder::encodeFixed32(std::vector<uint8_t>& buffer, uint32_t value)
{
	buffer.push_back((uint8_t)(value & 0xFF));
	buffer.push_back((uint8_t)((value >> 8) & 0xFF));
	buffer.push_back((uint8_t)((value >> 16) & 0xFF));
	buffer.push_back((uint8_t)((value >> 24) & 0xFF));
}

void MeshtasticEncoder::encodeLengthDelimited(std::vector<uint8_t>& buffer,
											   uint32_t field_number,
											   const std::vector<uint8_t>& data)
{
	// Field tag: (field_number << 3) | 2 (wire type 2 = length-delimited)
	encodeVarint(buffer, (field_number << 3) | 2);
	
	// Length (varint)
	encodeVarint(buffer, data.size());
	
	// Data
	buffer.insert(buffer.end(), data.begin(), data.end());
}

void MeshtasticEncoder::encodeString(std::vector<uint8_t>& buffer,
									 uint32_t field_number,
									 const std::string& str)
{
	std::vector<uint8_t> str_bytes(str.begin(), str.end());
	encodeLengthDelimited(buffer, field_number, str_bytes);
}

void MeshtasticEncoder::encodeVarintField(std::vector<uint8_t>& buffer,
										  uint32_t field_number,
										  uint64_t value)
{
	// Field tag: (field_number << 3) | 0 (wire type 0 = varint)
	encodeVarint(buffer, (field_number << 3) | 0);
	encodeVarint(buffer, value);
}

void MeshtasticEncoder::encodeFixed32Field(std::vector<uint8_t>& buffer,
										   uint32_t field_number,
										   uint32_t value)
{
	// Field tag: (field_number << 3) | 5 (wire type 5 = fixed32)
	encodeVarint(buffer, (field_number << 3) | 5);
	encodeFixed32(buffer, value);
}

// Packet construction

std::vector<uint8_t> MeshtasticEncoder::buildHeader(uint32_t to_address,
													 uint32_t from_address,
													 uint32_t packet_id,
													 uint8_t flags,
													 uint8_t channel,
													 uint8_t next_hop,
													 uint8_t relay_node)
{
	std::vector<uint8_t> header(16, 0);
	
	// to_address (4 bytes, little-endian)
	header[0] = to_address & 0xFF;
	header[1] = (to_address >> 8) & 0xFF;
	header[2] = (to_address >> 16) & 0xFF;
	header[3] = (to_address >> 24) & 0xFF;
	
	// from_address (4 bytes, little-endian)
	header[4] = from_address & 0xFF;
	header[5] = (from_address >> 8) & 0xFF;
	header[6] = (from_address >> 16) & 0xFF;
	header[7] = (from_address >> 24) & 0xFF;
	
	// packet_id (4 bytes, little-endian)
	header[8] = packet_id & 0xFF;
	header[9] = (packet_id >> 8) & 0xFF;
	header[10] = (packet_id >> 16) & 0xFF;
	header[11] = (packet_id >> 24) & 0xFF;
	
	// flags (1 byte)
	header[12] = flags;
	
	// channel (1 byte)
	header[13] = channel;
	
	// next_hop (1 byte)
	header[14] = next_hop;
	
	// relay_node (1 byte)
	header[15] = relay_node;
	
	return header;
}

std::vector<uint8_t> MeshtasticEncoder::buildNonce(uint32_t packet_id, uint32_t from_address)
{
	std::vector<uint8_t> nonce(16, 0);
	
	// Packet ID (4 bytes, little-endian)
	nonce[0] = packet_id & 0xFF;
	nonce[1] = (packet_id >> 8) & 0xFF;
	nonce[2] = (packet_id >> 16) & 0xFF;
	nonce[3] = (packet_id >> 24) & 0xFF;
	
	// Zero padding (4 bytes) - already zero
	
	// Sender Address (4 bytes, little-endian)
	nonce[8] = from_address & 0xFF;
	nonce[9] = (from_address >> 8) & 0xFF;
	nonce[10] = (from_address >> 16) & 0xFF;
	nonce[11] = (from_address >> 24) & 0xFF;
	
	// Zero padding (4 bytes) - already zero
	
	return nonce;
}

uint32_t MeshtasticEncoder::generatePacketId()
{
	uint32_t id = 0;
	
#ifdef ARDUINO
	// ESP32: Use hardware random number generator combined with multiple entropy sources
	// 1. esp_random() - hardware RNG
	// 2. millis() - time since boot (varies each boot)
	// 3. ADC noise - read from floating analog pin for additional entropy
	uint32_t r1 = esp_random();
	uint32_t r2 = esp_random();
	uint32_t r3 = esp_random();
	uint32_t time_entropy = (uint32_t)millis();  // Time since boot (varies each boot)
	
	// Read ADC noise for additional entropy
	// Even reading from a connected pin (like battery) multiple times gives
	// slight variations due to ADC noise, temperature, power supply ripple, etc.
	// We read multiple times with delays to capture these variations
	uint32_t adc_noise = 0;
	for (int i = 0; i < 8; i++) {
		// Read from battery pin (GPIO1) - even if connected, ADC has noise
		// Multiple reads with delays capture temperature/power variations
		uint16_t adc_val = analogRead(1);  // Read ADC channel 1 (GPIO1 - battery)
		adc_noise ^= ((uint32_t)adc_val << ((i % 4) * 8)) | ((uint32_t)adc_val >> (24 - (i % 4) * 8));
		// Small delay to let ADC settle and capture different noise samples
		delayMicroseconds(5);
	}
	
	// Debug output to verify randomness
	Serial.printf("[PacketID] r1=0x%08X r2=0x%08X r3=0x%08X millis=%lu adc=0x%08X\n", 
	              r1, r2, r3, (unsigned long)time_entropy, adc_noise);
	
	// Combine all entropy sources with XOR and bit rotations
	id = r1;
	id ^= (r2 << 16) | (r2 >> 16);  // Rotate r2
	id ^= r3;
	id ^= time_entropy;
	id ^= (time_entropy << 16) | (time_entropy >> 16);  // Rotate time_entropy
	id ^= adc_noise;
	id ^= (adc_noise << 8) | (adc_noise >> 24);  // Rotate ADC noise
	
	// Final mixing with another random value
	id ^= esp_random();
#else
	// macOS/other: Use std::random_device for randomness
	static std::random_device rd;
	static std::mt19937 gen(rd());
	static std::uniform_int_distribution<uint32_t> dis(1, 0xFFFFFFFF);
	id = dis(gen);
#endif
	
	// Ensure non-zero
	if (id == 0)
	{
		// If still zero, use a combination of time and a constant
		id = (uint32_t)(millis() ^ 0x12345678);
		if (id == 0) id = 1;
	}
	
	return id;
}

bool MeshtasticEncoder::encryptPayload(const std::vector<uint8_t>& plaintext,
									   std::vector<uint8_t>& ciphertext,
									   uint32_t packet_id,
									   uint32_t from_address,
									   const std::vector<uint8_t>& psk)
{
	// Build nonce
	std::vector<uint8_t> nonce = buildNonce(packet_id, from_address);
	
	// Use provided PSK or default
	const std::vector<uint8_t>& key = psk.empty() ? DEFAULT_PSK : psk;
	
	if (key.size() != 16)
	{
		return false;
	}
	
	// Initialize AES
	AES128Barebones aes;
	aes.setKey(key.data());
	
	// Encrypt (CTR mode - encryption and decryption are the same)
	ciphertext.resize(plaintext.size());
	aes.decryptCTR(plaintext.data(),
				   ciphertext.data(),
				   plaintext.size(),
				   nonce.data());
	
	return true;
}

// Text message encoding

MeshtasticEncoder::EncodedPacket MeshtasticEncoder::encodeTextMessage(
	const TextMessage& msg,
	uint32_t from_address,
	const std::vector<uint8_t>& psk)
{
	EncodedPacket result;
	result.success = false;
	
	// Validate input
	if (msg.text.empty() || msg.text.size() > 240)
	{
		result.error_message = "Text message must be 1-240 characters";
		return result;
	}
	
	// Generate packet ID
	uint32_t packet_id = generatePacketId();
	
	// Build protobuf payload
	// Structure: 08 [port=1] 12 [length] [text_data]
	std::vector<uint8_t> payload;
	
	// Field 1: port (varint) = 1 (TEXT_MESSAGE_APP)
	encodeVarintField(payload, 1, 1);
	
	// Field 2: payload (length-delimited) containing text
	std::vector<uint8_t> text_bytes(msg.text.begin(), msg.text.end());
	encodeLengthDelimited(payload, 2, text_bytes);
	
	// Encrypt payload
	std::vector<uint8_t> encrypted_payload;
	if (!encryptPayload(payload, encrypted_payload, packet_id, from_address, psk))
	{
		result.error_message = "Failed to encrypt payload";
		return result;
	}
	
	// Build header
	// Flags byte encoding (from Meshtastic protocol):
	// Bits 0-2: current hop_limit (remaining hops)
	// Bits 5-7: hop_start (original hop limit)
	// For a new packet: hop_limit = hop_start = msg.hop_limit
	uint8_t flags = (msg.hop_limit & 0x07) | ((msg.hop_limit & 0x07) << 5);
	uint8_t next_hop = 0;
	uint8_t relay_node = 0;
	std::vector<uint8_t> header = buildHeader(msg.to_address,
											  from_address,
											  packet_id,
											  flags,
											  msg.channel,
											  next_hop,
											  relay_node);
	
	// Combine header + encrypted payload
	result.data = header;
	result.data.insert(result.data.end(),
					  encrypted_payload.begin(),
					  encrypted_payload.end());
	
	result.success = true;
	return result;
}

// NodeInfo encoding

MeshtasticEncoder::EncodedPacket MeshtasticEncoder::encodeNodeInfo(
	const NodeInfo& nodeinfo,
	uint32_t from_address,
	const std::vector<uint8_t>& psk)
{
	EncodedPacket result;
	result.success = false;
	
	// Validate input
	if (nodeinfo.node_id == 0)
	{
		result.error_message = "Node ID cannot be zero";
		return result;
	}
	
	// Generate packet ID
	uint32_t packet_id = generatePacketId();
	
	// Build User protobuf message
	std::vector<uint8_t> user_protobuf;
	
	// Field 1: id (string)
	if (!nodeinfo.id.empty())
	{
		encodeString(user_protobuf, 1, nodeinfo.id);
	}
	
	// Field 2: long_name (string)
	if (!nodeinfo.long_name.empty())
	{
		encodeString(user_protobuf, 2, nodeinfo.long_name);
	}
	
	// Field 3: short_name (string)
	if (!nodeinfo.short_name.empty())
	{
		encodeString(user_protobuf, 3, nodeinfo.short_name);
	}
	
	// Field 5: hw_model (varint enum)
	if (nodeinfo.hw_model != 0)
	{
		encodeVarintField(user_protobuf, 5, nodeinfo.hw_model);
	}
	
	// Field 6: is_licensed (bool varint)
	encodeVarintField(user_protobuf, 6, nodeinfo.is_licensed ? 1 : 0);
	
	// Field 7: role (varint enum)
	if (nodeinfo.role != 0)
	{
		encodeVarintField(user_protobuf, 7, nodeinfo.role);
	}
	
	// Field 8: public_key (bytes, 32 bytes)
	std::vector<uint8_t> public_key_bytes(nodeinfo.public_key, nodeinfo.public_key + 32);
	encodeLengthDelimited(user_protobuf, 8, public_key_bytes);
	
	// Field 9: is_unmessagable (bool varint)
	encodeVarintField(user_protobuf, 9, nodeinfo.is_unmessagable ? 1 : 0);
	
	// Build Data protobuf message
	// Structure: 08 [port=4] 12 [length] [user_protobuf_data]
	std::vector<uint8_t> payload;
	
	// Field 1: port (varint) = 4 (NODEINFO_APP)
	encodeVarintField(payload, 1, 4);
	
	// Field 2: payload (length-delimited) containing User protobuf
	encodeLengthDelimited(payload, 2, user_protobuf);
	
	// Encrypt payload
	std::vector<uint8_t> encrypted_payload;
	if (!encryptPayload(payload, encrypted_payload, packet_id, from_address, psk))
	{
		result.error_message = "Failed to encrypt payload";
		return result;
	}
	
	// Build header
	// Flags byte encoding (from Meshtastic protocol):
	// Bits 0-2: current hop_limit (remaining hops)
	// Bits 5-7: hop_start (original hop limit)
	// For a new packet: hop_limit = hop_start = nodeinfo.hop_limit
	uint8_t flags = (nodeinfo.hop_limit & 0x07) | ((nodeinfo.hop_limit & 0x07) << 5);
	uint8_t next_hop = 0;
	uint8_t relay_node = 0;
	std::vector<uint8_t> header = buildHeader(0xFFFFFFFF,  // Broadcast
											  from_address,
											  packet_id,
											  flags,
											  0,  // Default channel
											  next_hop,
											  relay_node);
	
	// Combine header + encrypted payload
	result.data = header;
	result.data.insert(result.data.end(),
					  encrypted_payload.begin(),
					  encrypted_payload.end());
	
	result.success = true;
	return result;
}

// Position encoding

MeshtasticEncoder::EncodedPacket MeshtasticEncoder::encodePosition(
	const Position& position,
	uint32_t from_address,
	const std::vector<uint8_t>& psk)
{
	EncodedPacket result;
	result.success = false;
	
	// Validate input
	if (position.latitude < -90.0 || position.latitude > 90.0 ||
		position.longitude < -180.0 || position.longitude > 180.0)
	{
		result.error_message = "Invalid latitude/longitude";
		return result;
	}
	
	// Generate packet ID
	uint32_t packet_id = generatePacketId();
	
	// Build Position protobuf message
	std::vector<uint8_t> position_protobuf;
	
	// Field 1: latitude_i (fixed32) - latitude * 1e7
	int32_t latitude_i = (int32_t)(position.latitude * 1e7);
	encodeFixed32Field(position_protobuf, 1, (uint32_t)latitude_i);
	
	// Field 2: longitude_i (fixed32) - longitude * 1e7
	int32_t longitude_i = (int32_t)(position.longitude * 1e7);
	encodeFixed32Field(position_protobuf, 2, (uint32_t)longitude_i);
	
	// Field 3: altitude (int32 varint) - altitude in meters
	// Note: The decoder casts directly without zigzag decoding, so we encode
	// the value directly as unsigned varint (works for positive values)
	// For negative altitudes, this won't work correctly, but matches decoder behavior
	if (position.altitude != 0)
	{
		// Encode as unsigned varint (decoder expects this)
		uint64_t alt_unsigned = (uint64_t)(int64_t)position.altitude;
		encodeVarintField(position_protobuf, 3, alt_unsigned);
	}
	
	// Field 4: time (fixed32) - timestamp
	if (position.time != 0)
	{
		encodeFixed32Field(position_protobuf, 4, position.time);
	}
	
	// Field 5: location_source (varint enum)
	if (position.location_source != 0)
	{
		encodeVarintField(position_protobuf, 5, position.location_source);
	}
	
	// Field 6: altitude_source (varint enum)
	if (position.altitude_source != 0)
	{
		encodeVarintField(position_protobuf, 6, position.altitude_source);
	}
	
	// Field 7: timestamp (fixed32) - position timestamp
	if (position.timestamp != 0)
	{
		encodeFixed32Field(position_protobuf, 7, position.timestamp);
	}
	
	// Field 11: precision_bits (varint)
	if (position.precision_bits != 0)
	{
		encodeVarintField(position_protobuf, 11, position.precision_bits);
	}
	
	// Field 20: sats_in_view (varint)
	if (position.sats_in_view != 0)
	{
		encodeVarintField(position_protobuf, 20, position.sats_in_view);
	}
	
	// Field 21: ground_speed (varint) - m/s
	if (position.ground_speed != 0)
	{
		encodeVarintField(position_protobuf, 21, position.ground_speed);
	}
	
	// Field 22: ground_track (varint) - 1/100 degrees
	if (position.ground_track != 0)
	{
		encodeVarintField(position_protobuf, 22, position.ground_track);
	}
	
	// Build Data protobuf message
	// Structure: 08 [port=3] 12 [length] [position_protobuf_data]
	std::vector<uint8_t> payload;
	
	// Field 1: port (varint) = 3 (POSITION_APP)
	encodeVarintField(payload, 1, 3);
	
	// Field 2: payload (length-delimited) containing Position protobuf
	encodeLengthDelimited(payload, 2, position_protobuf);
	
	// Encrypt payload
	std::vector<uint8_t> encrypted_payload;
	if (!encryptPayload(payload, encrypted_payload, packet_id, from_address, psk))
	{
		result.error_message = "Failed to encrypt payload";
		return result;
	}
	
	// Build header
	// Flags byte encoding (from Meshtastic protocol):
	// Bits 0-2: current hop_limit (remaining hops)
	// Bits 5-7: hop_start (original hop limit)
	// For a new packet: hop_limit = hop_start = position.hop_limit
	uint8_t flags = (position.hop_limit & 0x07) | ((position.hop_limit & 0x07) << 5);
	uint8_t next_hop = 0;
	uint8_t relay_node = 0;
	std::vector<uint8_t> header = buildHeader(0xFFFFFFFF,  // Broadcast
											  from_address,
											  packet_id,
											  flags,
											  0,  // Default channel
											  next_hop,
											  relay_node);
	
	// Combine header + encrypted payload
	result.data = header;
	result.data.insert(result.data.end(),
					  encrypted_payload.begin(),
					  encrypted_payload.end());
	
	result.success = true;
	return result;
}

