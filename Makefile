SHELL := /bin/bash

BUILD_DIR := $(shell pwd)/build

#################################################

SRCS := $(wildcard *.cpp)
EXE  := $(patsubst %.cpp, %, $(SRCS))

#################################################

.PHONY: all clean check-all checks

all: $(BUILD_DIR) $(EXE)

$(BUILD_DIR):
	@echo "Creating build dir..."
	@mkdir -p $@

$(EXE): $(BUILD_DIR) 
	@echo "Building executable $@"
	@$(CXX) -o $(BUILD_DIR)/$@ $@.cpp $(FLAGS) -std=c++17
	@echo "Build $@ Complete!"
	@echo ""

clean:
	rm -rf $(BUILD_DIR)

check-all: checks

checks:
	@echo "Output directory:"
	@echo $(BUILD_DIR)
	@echo "--------------------------------------------"
	@echo "SRCS:"
	@echo $(SRCS)
	@echo "--------------------------------------------"
	@echo "EXE:"
	@echo $(EXE)
	@echo "--------------------------------------------"
