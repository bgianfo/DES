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
#include "blockmode.hpp"


void usage( char file[] ) {
  printf( "Usage: %s <infile> <outfile> key\n ", file );
}

int main( int argc, char* argv[] ) {

  if ( argc < 4 || argc > 4 ) {
    usage( argv[0] );
  }


    /* uint8_t msg[64] = { 0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,
                      0,1,1,0,0,1,1,1,1,0,0,0,1,0,0,1,1,0,1,0,1,0,1,1,
                      1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1 };

  uint8_t key[64] = { 0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,0,0,0,1};
  */

  char* key = argv[3];
  BLOCKMODE encrypter;
  encrypter.encrypt( argv[1], argv[2], key );
  /*
  for ( int i = 0; i < 1000000; i++ ) {
    DES cipher( msg, key );
    cipher.encrypt();
  }
  */

  return 0;
}
