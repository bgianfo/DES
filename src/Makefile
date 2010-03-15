CXX = g++
CFLAGS = -g -Wall -Wextra -ansi -pendantic
LFLAGS = 

default: encrypt decrypt

encrypt: encrypt.cpp
	$(CXX) -o encrypt $(LFLAGS) $(CFLAGS) des.cpp encrypt.cpp

decrypt: decrypt.cpp
	$(CXX) -o decrypt $(LFLAGS) $(CFLAGS) des.cpp decrypt.cpp


clean:
	rm -rf encrypt
	rm -rf decrypt
	rm -rf decrypt.dSYM
	rm -rf encrypt.dSYM
	rm -rf *.o
