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

default: encrypt decrypt encrypt_opt decrypt_opt


encrypt: encrypt.cpp des_original.hpp des_original.cpp blockmode.cpp blockmode.hpp
	$(CXX) -o encrypt_orig $(LFLAGS) $(CFLAGS) des_original.cpp encrypt.cpp blockmode.cpp

decrypt: decrypt.cpp des_original.hpp des_original.cpp blockmode.cpp blockmode.hpp
	$(CXX) -o decrypt_orig $(LFLAGS) $(CFLAGS) des_original.cpp decrypt.cpp blockmode.cpp

encrypt_opt: encrypt.cpp des.hpp des.cpp blockmode.cpp blockmode.hpp
	$(CXX) -o encrypt_opt $(LFLAGS) $(CFLAGS) -DDESOPTIMIZED des.cpp encrypt.cpp blockmode.cpp

decrypt_opt: decrypt.cpp des.hpp des.cpp blockmode.cpp blockmode.hpp
	$(CXX) -o decrypt_opt $(LFLAGS) $(CFLAGS) -DDESOPTIMIZED des.cpp decrypt.cpp blockmode.cpp

tester: test.cpp des.hpp des.cpp blockmode.cpp blockmode.hpp performance.cpp
	$(CXX) -o tester_orig $(LFLAGS) -lgtest $(CFLAGS) -DUNITTEST blockmode.cpp des_original.cpp test.cpp
	$(CXX) -o perftest_orig $(LFLAGS) $(CFLAGS) des_original.cpp performance.cpp
	$(CXX) -o tester_opt $(LFLAGS) -lgtest $(CFLAGS) -DUNITTEST -DDESOPTIMIZED blockmode.cpp des.cpp test.cpp
	$(CXX) -o perftest_opt $(LFLAGS) $(CFLAGS) -DDESOPTIMIZED des.cpp performance.cpp

test: tester
	./tester_opt
	./tester_orig

clean:
	rm -rf tester_opt
	rm -rf encrypt_opt
	rm -rf decrypt_opt
	rm -rf perftest_opt
	rm -rf tester_orig
	rm -rf encrypt_orig
	rm -rf decrypt_orig
	rm -rf perftest_orig
	rm -rf decrypt*.dSYM
	rm -rf encrypt*.dSYM
	rm -rf tester*.dSYM
	rm -rf *.o
	clear
