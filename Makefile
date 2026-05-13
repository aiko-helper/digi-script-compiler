CXX      := g++
CXXFLAGS := -std=c++23 -Wall -Wextra -Wpedantic -O2 -g
LDFLAGS  :=

SRCS := $(wildcard *.cpp)
OBJS := $(SRCS:.cpp=.o)
DEPS := $(OBJS:.o=.d)

BIN  := digi-disasm

.PHONY: all clean parity

all: $(BIN)

$(BIN): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(BIN)

# Round-trip regression gate.  Splits + reassembles both shipping SCNs
# and compares to the originals.  Also diffs against tools/digi-disasm/golden/
# if present.
parity: $(BIN)
	./parity.sh


