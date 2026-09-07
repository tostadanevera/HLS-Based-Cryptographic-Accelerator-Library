CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2
BUILD_DIR := build
COMMON_HDR := common/types.h

ALGOS := aes chacha20 sha256 serpent sha3

.PHONY: test clean

.SECONDARY:

.DEFAULT_GOAL := test

.SECONDEXPANSION:

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/test_%: $$*/$$*.cpp $$*/$$*.h $$*/test_$$*.cpp $(COMMON_HDR) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -I. $*/$*.cpp $*/test_$*.cpp -o $@

test-%: $(BUILD_DIR)/test_%
	./$<

test: $(addprefix test-,$(ALGOS))

clean:
	rm -rf $(BUILD_DIR)