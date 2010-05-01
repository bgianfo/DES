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

  char* key = argv[3];
  BLOCKMODE encrypter;
  encrypter.decrypt( argv[1], argv[2], key );

  return 0;
}
