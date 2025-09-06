#ifndef AES_BAREBONES_H
#define AES_BAREBONES_H

#include <cstddef>
#include <stdint.h>
#include <string>
#include <vector>

class AES128Barebones
{
  public:
	// Constructor
	AES128Barebones();

	// Set the encryption key (16 bytes)
	void setKey(const uint8_t* key);

	// CTR mode decryption (same as encryption for CTR)
	void decryptCTR(const uint8_t* input,
					uint8_t* output,
					size_t length,
					const uint8_t* nonce);

	// Utility function to convert hex string to bytes
	static std::vector<uint8_t> hexToBytes(const std::string& hex_string);

	// Utility function to convert bytes to hex string
	static std::string bytesToHex(const uint8_t* data, size_t length);

  private:
	uint8_t key[16];
	uint8_t roundKeys[176]; // 11 rounds * 16 bytes per round key

	// AES core functions
	void keyExpansion();
	void addRoundKey(uint8_t state[16], int round);
	void subBytes(uint8_t state[16]);
	void shiftRows(uint8_t state[16]);
	void mixColumns(uint8_t state[16]);
	void invSubBytes(uint8_t state[16]);
	void invShiftRows(uint8_t state[16]);
	void invMixColumns(uint8_t state[16]);

	// Helper functions
	uint8_t gfMultiply(uint8_t a, uint8_t b);
	void rotWord(uint8_t word[4]);
	void subWord(uint8_t word[4]);

	// S-box and inverse S-box
	static const uint8_t sbox[256];
	static const uint8_t inv_sbox[256];
	static const uint8_t rcon[11];
};

#endif // AES_BAREBONES_H
