#ifndef MESHTASTIC_DECODER_H
#define MESHTASTIC_DECODER_H

#include <cstdint>
#include <string>
#include <vector>

/**
 * MeshtasticDecoder - Library interface for decoding Meshtastic radio packets
 * 
 * This class provides a pure C++ implementation for decoding Meshtastic packets
 * with no external dependencies. It supports TEXT_MESSAGE_APP, POSITION_APP,
 * NODEINFO_APP, TRACEROUTE_APP, and TELEMETRY_APP.
 * 
 * Usage:
 *   MeshtasticDecoder decoder;
 *   std::vector<uint8_t> raw_data = ...; // raw packet bytes
 *   MeshtasticDecoder::DecodedPacket result = decoder.decodePacket(raw_data);
 *   if (result.success) {
 *     // Access decoded fields from result
 *   }
 */
class MeshtasticDecoder
{
  public:
	/**
	 * DecodedPacket - Structure containing all decoded packet information
	 */
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
		uint32_t sats_in_view;
		uint32_t sats_in_use;
		uint32_t ground_speed;
		double ground_track; // in degrees (converted from 1/100 degrees)
		uint32_t gps_accuracy; // in mm
		// DOP (Dilution of Precision) values - in units (stored as 1/100, converted when displayed)
		double pdop; // Position DOP
		double hdop; // Horizontal DOP
		double vdop; // Vertical DOP
		uint32_t fix_quality;
		uint32_t fix_type;
		uint32_t precision_bits;
		int32_t altitude_hae; // HAE altitude in meters
		int32_t altitude_geoidal_separation; // Geoidal separation in meters
		uint32_t location_source; // enum LocationSource: 0=LOC_UNSET, 1=LOC_MANUAL, 2=LOC_INTERNAL, 3=LOC_EXTERNAL
		uint32_t altitude_source; // enum AltitudeSource: 0=ALT_UNSET, 1=ALT_MANUAL, 2=ALT_INTERNAL, 3=ALT_EXTERNAL, 4=ALT_BAROMETRIC
		int32_t timestamp_millis_adjust;
		uint32_t sensor_id;
		uint32_t next_update; // seconds until next update
		uint32_t seq_number;

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
		std::vector<uint32_t> route_back_nodes;
		std::vector<int32_t> snr_towards;
		std::vector<int32_t> snr_back;
		std::string route_path;
		std::string route_back_path;
		int route_count;
		int route_back_count;
		std::string route_type; // "route_request" or "route_reply"
		
		// Telemetry data (for TELEMETRY_APP)
		std::string telemetry_info;
		std::string raw_telemetry_hex;
		std::string telemetry_type; // device_metrics, environment_metrics, etc.
		uint32_t telemetry_time;
		
		// DeviceMetrics fields
		uint32_t battery_level;
		float voltage;
		float channel_utilization;
		float air_util_tx;
		uint32_t uptime_seconds;
		
		// EnvironmentMetrics fields
		float temperature;
		float relative_humidity;
		float barometric_pressure;
		float gas_resistance;
		float current;
		uint32_t iaq;
		float distance;
		float lux;
		float white_lux;
		float ir_lux;
		float uv_lux;
		uint32_t wind_direction;
		float wind_speed;
		float weight;
		float wind_gust;
		float wind_lull;
		float radiation;
		float rainfall_1h;
		float rainfall_24h;
		uint32_t soil_moisture;
		float soil_temperature;
		
		// AirQualityMetrics fields
		uint32_t pm10_standard;
		uint32_t pm25_standard;
		uint32_t pm100_standard;
		uint32_t pm10_environmental;
		uint32_t pm25_environmental;
		uint32_t pm100_environmental;
		uint32_t particles_03um;
		uint32_t particles_05um;
		uint32_t particles_10um;
		uint32_t particles_25um;
		uint32_t particles_50um;
		uint32_t particles_100um;
		uint32_t co2;
		float co2_temperature;
		float co2_humidity;
		float form_formaldehyde;
		float form_humidity;
		float form_temperature;
		
		// PowerMetrics fields (ch1-ch8 voltage/current)
		float ch1_voltage, ch1_current;
		float ch2_voltage, ch2_current;
		float ch3_voltage, ch3_current;
		float ch4_voltage, ch4_current;
		float ch5_voltage, ch5_current;
		float ch6_voltage, ch6_current;
		float ch7_voltage, ch7_current;
		float ch8_voltage, ch8_current;
		
		// LocalStats fields
		uint32_t num_packets_tx;
		uint32_t num_packets_rx;
		uint32_t num_packets_rx_bad;
		uint32_t num_online_nodes;
		uint32_t num_total_nodes;
		uint32_t num_rx_dupe;
		uint32_t num_tx_relay;
		uint32_t num_tx_relay_canceled;
		uint32_t heap_total_bytes;
		uint32_t heap_free_bytes;
		uint32_t num_tx_dropped;
		
		// HealthMetrics fields
		uint32_t heart_bpm;
		uint32_t spO2;
		float body_temperature;
		
		// HostMetrics fields
		uint64_t freemem_bytes;
		uint64_t diskfree1_bytes;
		uint64_t diskfree2_bytes;
		uint64_t diskfree3_bytes;
		uint32_t load1;
		uint32_t load5;
		uint32_t load15;
		std::string host_user_string;
		
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

	/**
	 * Main decoding function
	 * @param raw_data Raw packet bytes (including 16-byte header)
	 * @return DecodedPacket structure with all decoded information
	 */
	DecodedPacket decodePacket(const std::vector<uint8_t>& raw_data);

	/**
	 * Convert decoded packet to JSON string
	 * @param packet Decoded packet structure
	 * @return JSON string representation
	 */
	std::string toJson(const DecodedPacket& packet);

	/**
	 * Utility: Convert hex string to byte vector
	 * @param hex_string Hex string (spaces optional)
	 * @return Vector of bytes
	 */
	static std::vector<uint8_t> hexStringToBytes(const std::string& hex_string);

	/**
	 * Utility: Convert byte vector to hex string
	 * @param data Byte vector
	 * @return Hex string
	 */
	static std::string bytesToHexString(const std::vector<uint8_t>& data);

	/**
	 * Protobuf decoding for position data (public for testing)
	 * @param data Protobuf data bytes
	 * @param packet DecodedPacket structure to populate
	 * @return true if successful
	 */
	bool decodePosition(const std::vector<uint8_t>& data, DecodedPacket& packet);

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
	bool decodeProtobuf(const std::vector<uint8_t>& data, DecodedPacket& packet);
	void decodeMeshPacketFields(const std::vector<uint8_t>& data, DecodedPacket& packet);
	bool decodeTextMessage(const std::vector<uint8_t>& data, DecodedPacket& packet);
	bool decodeNodeInfo(const std::vector<uint8_t>& data, DecodedPacket& packet);
	bool decodeTelemetry(const std::vector<uint8_t>& data, DecodedPacket& packet);
	bool decodeTraceroute(const std::vector<uint8_t>& data, DecodedPacket& packet);
	uint64_t decodeVarint(const std::vector<uint8_t>& data, size_t& offset);
	float decodeFloat(const std::vector<uint8_t>& data, size_t& offset);
	uint64_t decodeUint64(const std::vector<uint8_t>& data, size_t& offset);
	
	// Telemetry sub-message decoders
	void decodeDeviceMetrics(const std::vector<uint8_t>& data, DecodedPacket& packet);
	void decodeEnvironmentMetrics(const std::vector<uint8_t>& data, DecodedPacket& packet);
	void decodeAirQualityMetrics(const std::vector<uint8_t>& data, DecodedPacket& packet);
	void decodePowerMetrics(const std::vector<uint8_t>& data, DecodedPacket& packet);
	void decodeLocalStats(const std::vector<uint8_t>& data, DecodedPacket& packet);
	void decodeHealthMetrics(const std::vector<uint8_t>& data, DecodedPacket& packet);
	void decodeHostMetrics(const std::vector<uint8_t>& data, DecodedPacket& packet);
	
	// Traceroute sub-message decoders
	void decodeRouteDiscovery(const std::vector<uint8_t>& data, DecodedPacket& packet);
	void formatRoutePath(const std::vector<uint32_t>& nodes, std::string& path);
	
	// Skip and routing calculation
	void calculateSkipAndRouting(DecodedPacket& packet);
	
	// Utility functions
	static std::string escapeJsonString(const std::string& str);
	static std::string formatDouble(double value, int precision = 7);
};

#endif // MESHTASTIC_DECODER_H

