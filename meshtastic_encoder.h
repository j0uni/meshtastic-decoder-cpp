#ifndef MESHTASTIC_ENCODER_H
#define MESHTASTIC_ENCODER_H

#include <cstdint>
#include <string>
#include <vector>

/**
 * MeshtasticEncoder - Library interface for encoding Meshtastic radio packets
 * 
 * This class provides a pure C++ implementation for encoding Meshtastic packets
 * with no external dependencies. It supports TEXT_MESSAGE_APP, POSITION_APP,
 * and NODEINFO_APP with AES-128-CTR encryption.
 * 
 * Usage:
 *   MeshtasticEncoder encoder;
 *   MeshtasticEncoder::TextMessage msg;
 *   msg.text = "Hello, Meshtastic!";
 *   msg.to_address = 0xFFFFFFFF;  // Broadcast
 *   auto result = encoder.encodeTextMessage(msg, my_node_id);
 *   if (result.success) {
 *     // Send result.data over radio
 *   }
 */
class MeshtasticEncoder
{
  public:
	/**
	 * TextMessage - Structure for encoding text messages
	 */
	struct TextMessage
	{
		std::string text;           // Message text (UTF-8)
		uint32_t to_address;        // Destination node ID (0xFFFFFFFF for broadcast)
		uint8_t channel;            // Channel index (0 for default)
		uint8_t hop_limit;          // Maximum hops (default: 3)
		uint32_t request_id;       // Packet ID of message being replied to (0 if not a reply)
		uint32_t reply_id;         // Reply ID field (0 if not set)
		bool want_response;        // Want response flag (default: false)
	};

	/**
	 * NodeInfo - Structure for encoding node info packets
	 */
	struct NodeInfo
	{
		uint32_t node_id;           // Node ID
		std::string long_name;      // Long node name
		std::string short_name;     // Short node name
		std::string id;             // Node ID string (e.g., "!12345678")
		uint8_t hw_model;           // Hardware model enum
		uint8_t role;               // Device role enum
		bool is_licensed;           // Is licensed operator
		uint8_t public_key[32];     // Public key (32 bytes)
		bool is_unmessagable;       // Can receive messages?
		uint8_t hop_limit;           // Maximum hops (default: 3)
	};

	/**
	 * Position - Structure for encoding position packets
	 */
	struct Position
	{
		double latitude;            // Latitude in degrees
		double longitude;           // Longitude in degrees
		int32_t altitude;           // Altitude in meters
		uint32_t time;              // Unix timestamp (seconds)
		uint32_t timestamp;         // Position timestamp (seconds)
		uint8_t location_source;     // Location source enum (0=UNSET, 3=EXTERNAL)
		uint8_t altitude_source;    // Altitude source enum (0=UNSET, 3=EXTERNAL)
		uint32_t sats_in_view;      // Satellites in view
		uint32_t ground_speed;      // Ground speed (m/s)
		uint32_t ground_track;      // Ground track (1/100 degrees)
		uint8_t precision_bits;      // Precision bits (default: 32)
		uint8_t hop_limit;          // Maximum hops (default: 3)
	};

	/**
	 * EncodedPacket - Result of encoding operation
	 */
	struct EncodedPacket
	{
		std::vector<uint8_t> data;  // Complete packet bytes (header + encrypted payload)
		bool success;                  // True if encoding succeeded
		std::string error_message;     // Error description if failed
	};

	/**
	 * Encode a text message packet
	 * @param msg Text message structure
	 * @param from_address Source node ID
	 * @param channel_name Channel name for hash calculation (if empty, uses msg.channel as hash)
	 * @param psk Optional PSK (16 bytes). If empty, uses default PSK
	 * @return EncodedPacket with complete packet bytes
	 */
	EncodedPacket encodeTextMessage(const TextMessage& msg,
									uint32_t from_address,
									const std::string& channel_name = "",
									const std::vector<uint8_t>& psk = {});

	/**
	 * Encode a node info packet
	 * @param nodeinfo Node info structure
	 * @param from_address Source node ID (should match nodeinfo.node_id)
	 * @param channel_name Channel name for hash calculation (if empty, uses default channel)
	 * @param psk Optional PSK (16 bytes). If empty, uses default PSK
	 * @return EncodedPacket with complete packet bytes
	 */
	EncodedPacket encodeNodeInfo(const NodeInfo& nodeinfo,
								 uint32_t from_address,
								 const std::string& channel_name = "",
								 const std::vector<uint8_t>& psk = {});

	/**
	 * Encode a position packet
	 * @param position Position structure
	 * @param from_address Source node ID
	 * @param psk Optional PSK (16 bytes). If empty, uses default PSK
	 * @return EncodedPacket with complete packet bytes
	 */
	EncodedPacket encodePosition(const Position& position,
								 uint32_t from_address,
								 const std::vector<uint8_t>& psk = {});

	/**
	 * Calculate channel hash from channel name and PSK
	 * @param channel_name Channel name string
	 * @param psk Optional PSK (16 bytes). If empty, uses default PSK
	 * @return Channel hash byte
	 */
	static uint8_t calculateChannelHash(const std::string& channel_name,
										const std::vector<uint8_t>& psk = {});

  private:
	// Default PSK (same as decoder)
	static const std::vector<uint8_t> DEFAULT_PSK;

	// Protobuf encoding utilities
	void encodeVarint(std::vector<uint8_t>& buffer, uint64_t value);
	void encodeFixed32(std::vector<uint8_t>& buffer, uint32_t value);
	void encodeLengthDelimited(std::vector<uint8_t>& buffer,
							   uint32_t field_number,
							   const std::vector<uint8_t>& data);
	void encodeString(std::vector<uint8_t>& buffer,
					 uint32_t field_number,
					 const std::string& str);
	void encodeVarintField(std::vector<uint8_t>& buffer,
						  uint32_t field_number,
						  uint64_t value);
	void encodeFixed32Field(std::vector<uint8_t>& buffer,
							   uint32_t field_number,
							   uint32_t value);

	// Packet construction
	std::vector<uint8_t> buildHeader(uint32_t to_address,
									 uint32_t from_address,
									 uint32_t packet_id,
									 uint8_t flags,
									 uint8_t channel,
									 uint8_t next_hop,
									 uint8_t relay_node);
	std::vector<uint8_t> buildNonce(uint32_t packet_id, uint32_t from_address);
	uint32_t generatePacketId();

	// Encryption
	bool encryptPayload(const std::vector<uint8_t>& plaintext,
					   std::vector<uint8_t>& ciphertext,
					   uint32_t packet_id,
					   uint32_t from_address,
					   const std::vector<uint8_t>& psk);

	// Channel hash calculation
	static uint8_t xorHash(const uint8_t* data, size_t len);
};

#endif // MESHTASTIC_ENCODER_H

