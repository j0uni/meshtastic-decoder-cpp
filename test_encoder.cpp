#include "meshtastic_encoder.h"
#include "meshtastic_decoder.h"
#include <iostream>
#include <iomanip>
#include <cstring>

void printHex(const std::vector<uint8_t>& data, const std::string& label)
{
	std::cout << label << " (" << data.size() << " bytes): ";
	for (size_t i = 0; i < data.size(); i++)
	{
		if (i > 0 && i % 16 == 0)
		{
			std::cout << "\n" << std::string(label.length() + 2, ' ');
		}
		std::cout << std::hex << std::setfill('0') << std::setw(2) 
				  << (int)data[i] << " ";
	}
	std::cout << std::dec << std::endl;
}

bool testTextMessage()
{
	std::cout << "\n=== Testing Text Message Encoding ===\n";
	
	MeshtasticEncoder encoder;
	MeshtasticEncoder::TextMessage msg;
	msg.text = "Hello, Meshtastic!";
	msg.to_address = 0xFFFFFFFF;  // Broadcast
	msg.channel = 0;
	msg.hop_limit = 3;
	
	uint32_t from_address = 0x12345678;
	
	auto encoded = encoder.encodeTextMessage(msg, from_address);
	
	if (!encoded.success)
	{
		std::cout << "ERROR: " << encoded.error_message << std::endl;
		return false;
	}
	
	std::cout << "Encoded successfully (" << encoded.data.size() << " bytes)\n";
	printHex(encoded.data, "Encoded packet");
	
	// Test with decoder
	MeshtasticDecoder decoder;
	auto decoded = decoder.decodePacket(encoded.data);
	
	if (!decoded.success)
	{
		std::cout << "ERROR: Decoder failed: " << decoded.error_message << std::endl;
		return false;
	}
	
	std::cout << "\nDecoder results:\n";
	std::cout << "  Port: " << (int)decoded.port << " (expected: 1)\n";
	std::cout << "  Text: \"" << decoded.text_message << "\" (expected: \"" << msg.text << "\")\n";
	std::cout << "  From: 0x" << std::hex << decoded.from_address << std::dec 
			  << " (expected: 0x" << std::hex << from_address << std::dec << ")\n";
	
	bool success = (decoded.port == 1) && 
				   (decoded.text_message == msg.text) &&
				   (decoded.from_address == from_address);
	
	if (success)
	{
		std::cout << "\n✓ Text message test PASSED\n";
	}
	else
	{
		std::cout << "\n✗ Text message test FAILED\n";
	}
	
	return success;
}

bool testNodeInfo()
{
	std::cout << "\n=== Testing NodeInfo Encoding ===\n";
	
	MeshtasticEncoder encoder;
	MeshtasticEncoder::NodeInfo nodeinfo;
	nodeinfo.node_id = 0x12345678;
	nodeinfo.long_name = "Test Node";
	nodeinfo.short_name = "TEST";
	nodeinfo.id = "!12345678";
	nodeinfo.hw_model = 24;  // T_DECK
	nodeinfo.role = 0;  // CLIENT
	nodeinfo.is_licensed = false;
	memset(nodeinfo.public_key, 0xAA, 32);  // Dummy key
	nodeinfo.is_unmessagable = false;
	nodeinfo.hop_limit = 3;
	
	uint32_t from_address = nodeinfo.node_id;
	
	auto encoded = encoder.encodeNodeInfo(nodeinfo, from_address);
	
	if (!encoded.success)
	{
		std::cout << "ERROR: " << encoded.error_message << std::endl;
		return false;
	}
	
	std::cout << "Encoded successfully (" << encoded.data.size() << " bytes)\n";
	printHex(encoded.data, "Encoded packet");
	
	// Test with decoder
	MeshtasticDecoder decoder;
	auto decoded = decoder.decodePacket(encoded.data);
	
	if (!decoded.success)
	{
		std::cout << "ERROR: Decoder failed: " << decoded.error_message << std::endl;
		return false;
	}
	
	std::cout << "\nDecoder results:\n";
	std::cout << "  Port: " << (int)decoded.port << " (expected: 4)\n";
	std::cout << "  Node ID: \"" << decoded.node_id << "\" (expected: \"" << nodeinfo.id << "\")\n";
	std::cout << "  Long name: \"" << decoded.long_name << "\" (expected: \"" << nodeinfo.long_name << "\")\n";
	std::cout << "  Short name: \"" << decoded.short_name << "\" (expected: \"" << nodeinfo.short_name << "\")\n";
	
	bool success = (decoded.port == 4) && 
				   (decoded.node_id == nodeinfo.id) &&
				   (decoded.long_name == nodeinfo.long_name) &&
				   (decoded.short_name == nodeinfo.short_name);
	
	if (success)
	{
		std::cout << "\n✓ NodeInfo test PASSED\n";
	}
	else
	{
		std::cout << "\n✗ NodeInfo test FAILED\n";
	}
	
	return success;
}

bool testPosition()
{
	std::cout << "\n=== Testing Position Encoding ===\n";
	
	MeshtasticEncoder encoder;
	MeshtasticEncoder::Position position;
	position.latitude = 61.496003;
	position.longitude = 23.855086;
	position.altitude = 100;
	position.time = 1704067200;  // 2024-01-01 00:00:00 UTC
	position.timestamp = 1704067200;
	position.location_source = 3;  // EXTERNAL
	position.altitude_source = 3;  // EXTERNAL
	position.sats_in_view = 12;
	position.ground_speed = 0;
	position.ground_track = 0;
	position.precision_bits = 32;
	position.hop_limit = 3;
	
	uint32_t from_address = 0x12345678;
	
	auto encoded = encoder.encodePosition(position, from_address);
	
	if (!encoded.success)
	{
		std::cout << "ERROR: " << encoded.error_message << std::endl;
		return false;
	}
	
	std::cout << "Encoded successfully (" << encoded.data.size() << " bytes)\n";
	printHex(encoded.data, "Encoded packet");
	
	// Test with decoder
	MeshtasticDecoder decoder;
	auto decoded = decoder.decodePacket(encoded.data);
	
	if (!decoded.success)
	{
		std::cout << "ERROR: Decoder failed: " << decoded.error_message << std::endl;
		return false;
	}
	
	std::cout << "\nDecoder results:\n";
	std::cout << "  Port: " << (int)decoded.port << " (expected: 3)\n";
	std::cout << "  Latitude: " << std::fixed << std::setprecision(7) << decoded.latitude 
			  << " (expected: " << position.latitude << ")\n";
	std::cout << "  Longitude: " << decoded.longitude 
			  << " (expected: " << position.longitude << ")\n";
	std::cout << "  Altitude: " << decoded.altitude 
			  << " (expected: " << position.altitude << ")\n";
	
	// Allow small floating point differences
	double lat_diff = std::abs(decoded.latitude - position.latitude);
	double lon_diff = std::abs(decoded.longitude - position.longitude);
	
	bool success = (decoded.port == 3) && 
				   (lat_diff < 0.0001) &&
				   (lon_diff < 0.0001) &&
				   (decoded.altitude == position.altitude);
	
	if (success)
	{
		std::cout << "\n✓ Position test PASSED\n";
	}
	else
	{
		std::cout << "\n✗ Position test FAILED\n";
	}
	
	return success;
}

int main()
{
	std::cout << "Meshtastic Encoder Test\n";
	std::cout << "=======================\n";
	
	bool all_passed = true;
	
	all_passed &= testTextMessage();
	all_passed &= testNodeInfo();
	all_passed &= testPosition();
	
	std::cout << "\n=======================\n";
	if (all_passed)
	{
		std::cout << "All tests PASSED!\n";
		return 0;
	}
	else
	{
		std::cout << "Some tests FAILED!\n";
		return 1;
	}
}

