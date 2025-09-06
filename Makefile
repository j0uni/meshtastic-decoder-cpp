# Makefile for Meshtastic Decoder - Standalone Version
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -Werror -Wfatal-errors -O2
BUILD_DIR = build
SOURCE_DIR = .

# Source files for standalone decoder
STANDALONE_SOURCES = meshtastic_decoder_standalone.cpp aes_barebones.cpp
STANDALONE_OBJECTS = $(addprefix $(BUILD_DIR)/,$(STANDALONE_SOURCES:.cpp=.o))
STANDALONE_TARGET = $(BUILD_DIR)/meshtastic_decoder_standalone

# Default target
all: $(BUILD_DIR) $(STANDALONE_TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build the standalone decoder
$(STANDALONE_TARGET): $(STANDALONE_OBJECTS)
	$(CXX) $(STANDALONE_OBJECTS) -o $(STANDALONE_TARGET)

# Compile source files
$(BUILD_DIR)/%.o: $(SOURCE_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -rf $(BUILD_DIR)

# Run the test examples
test: $(STANDALONE_TARGET)
	./test_examples.sh

# Test individual packet types
test-text: $(STANDALONE_TARGET)
	$(STANDALONE_TARGET) "FF FF FF FF A8 E2 09 13 75 67 20 3A A5 08 00 A8 7A AB 93 44 8E 1B 21 29 68 5A CB 0A 12 E8 DB 91 D9 31 E6 18 BE 40 07 7E F8 11 BB"

test-position: $(STANDALONE_TARGET)
	$(STANDALONE_TARGET) "FF FF FF FF 98 E2 09 13 6E 6A 20 3A A5 08 00 A8 21 9F 5D BD 8F DF 6D 5E FB 6D 27 A3 B1 A0 1D 25 48 A9 D7 9F 5B 1A A6 DA 64 64 56 3C 95 91 BA B4 B4 9E F8 11 78 9A 65 CA 84 0F 28 B0 B0 E6 38 C7 76 3C F2 D4 79 B7 A8 F5 D6 38 B4 34 1E DE 22 06 1E EF 02 EF"

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the standalone decoder"
	@echo "  clean        - Remove build files"
	@echo "  test         - Run all test examples"
	@echo "  test-text    - Test text message decoding"
	@echo "  test-position- Test position decoding"
	@echo "  help         - Show this help message"

.PHONY: all clean test test-text test-position help
