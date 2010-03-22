##########################################################
#
#  File: des.hpp
#
#  Authors: 
# 
#     Sam Milton        (srm2997@cs.rit.edu)
#     Brian Gianforcaro (bjg1955@cs.rit.edu)
#
##########################################################

CXX = g++
CFLAGS = -g3 -pg -Wall -Wextra -ansi -pendantic
LFLAGS = 

default: encrypt decrypt tester test

encrypt: encrypt.cpp des.hpp des.cpp
	$(CXX) -o encrypt $(LFLAGS) $(CFLAGS) des.cpp encrypt.cpp

decrypt: decrypt.cpp des.hpp des.cpp
	$(CXX) -o decrypt $(LFLAGS) $(CFLAGS) des.cpp decrypt.cpp

tester: test.cpp des.hpp des.cpp
	$(CXX) -o tester $(LFLAGS) -lgtest $(CFLAGS) -DUNITTEST des.cpp test.cpp

test: tester
	./tester

clean:
	rm -rf encrypt
	rm -rf decrypt
	rm -rf tester
	rm -rf decrypt.dSYM
	rm -rf encrypt.dSYM
	rm -rf tester.dSYM
	rm -rf *.o
