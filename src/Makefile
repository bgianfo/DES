##########################################################
#
#  File: Makefile
#
#  Authors:
#
#     Sam Milton        (srm2997@cs.rit.edu)
#     Brian Gianforcaro (bjg1955@cs.rit.edu)
#
##########################################################

CXX = g++
#CXX = clang++
DEVLCFLAGS = -g3 -pg -Wall -Wextra -ansi -pedantic
DISTCFLAGS = -Wall -Wextra -O2 -fomit-frame-pointer

#CFLAGS = $(DISTCFLAGS)
CFLAGS = $(DEVLCFLAGS)
LFLAGS =

default: encrypt decrypt

encrypt: encrypt.cpp des.hpp des.cpp blockmode.cpp blockmode.hpp
	$(CXX) -o encrypt $(LFLAGS) $(CFLAGS) des.cpp encrypt.cpp blockmode.cpp

decrypt: decrypt.cpp des.hpp des.cpp blockmode.cpp blockmode.hpp
	$(CXX) -o decrypt $(LFLAGS) $(CFLAGS) des.cpp decrypt.cpp blockmode.cpp

tester: test.cpp des.hpp des.cpp blockmode.cpp blockmode.hpp performance.cpp
	$(CXX) -o tester $(LFLAGS) -lgtest $(CFLAGS) -DUNITTEST blockmode.cpp des.cpp test.cpp
	$(CXX) -o perftest $(LFLAGS) $(CFLAGS) des.cpp performance.cpp

test: tester
	./tester

clean:
	rm -rf encrypt
	rm -rf decrypt
	rm -rf tester
	rm -rf perftest
	rm -rf decrypt.dSYM
	rm -rf encrypt.dSYM
	rm -rf tester.dSYM
	rm -rf *.o
	clear
