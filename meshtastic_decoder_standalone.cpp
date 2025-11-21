#include "meshtastic_decoder.h"
#include <iostream>
#include <string>
#include <vector>

// Main function for standalone binary
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
	  MeshtasticDecoder::hexStringToBytes(hex_input);

	if (raw_data.empty())
	{
		std::cerr << "Error: Invalid hex data provided\n";
		return 1;
	}

	// Decode the packet
	MeshtasticDecoder decoder;
	MeshtasticDecoder::DecodedPacket result =
	  decoder.decodePacket(raw_data);

	// Output JSON
	std::cout << decoder.toJson(result) << std::endl;

	return result.success ? 0 : 1;
}
