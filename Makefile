default: hdown

CXX_FLAGS := -std=c++11 -O2 -Wall -Werror
#CXX_FLAGS := $(CXX_FLAGS) -fsanitize=address -ggdb3

default: hdown

hdown: src/hdown.cc src/http_parse.h
	$(CXX) $(CXX_FLAGS) src/hdown.cc -o hdown

clean:
	$(RM) ./hdown
