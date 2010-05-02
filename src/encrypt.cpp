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
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "blockmode.hpp"

using namespace std;

void usage( char file[] ) {
  cout << endl;
  cout << "Usage: " << file << " <infile> <outfile> <key>" << endl;
  cout << endl;
  cout << "  <infile>  - The file you wish to encrypt" << endl;
  cout << "  <outfile> - The resulting encrypted file" << endl;
  cout << "  <key>     - 8 character string for your key"<< endl;
  cout << endl;

  exit(EXIT_FAILURE);
}

int main( int argc, char* argv[] ) {

  if ( argc < 4 || argc > 4 ) {
    usage( argv[0] );
  }

  char* in  = argv[1];
  char* out = argv[2];
  char* key = argv[3];
  BLOCKMODE encrypter;
  encrypter.encrypt( in, out, key );

  return EXIT_SUCCESS;
}
