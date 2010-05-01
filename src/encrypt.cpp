/*
**  File: encrypt.cpp
**
**  Authors:
** 
**     Sam Milton
**     Brian Gianforcaro (bjg1955@cs.rit.edu)
**
*/

#include <cstdio>
#include <cstring>
#include "des.hpp"

int main( ) {

  uint8_t msg[64] = { 0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,
                      0,1,1,0,0,1,1,1,1,0,0,0,1,0,0,1,1,0,1,0,1,0,1,1,
                      1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1 };

  uint8_t key[64] = { 0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,0,0,0,1};

  for ( int i = 0; i < 1000000; i++ ) {
    DES cipher( msg, key );
    cipher.encrypt();
  }

  return 0;
}
