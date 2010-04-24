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

int main( int i, char **argv ) {

  char key[17] = "01334567";
  char msg[17] = "01234567";

  printf( "Encrypting: %s\n", msg );
  printf( "With Key: %s\n", key );

  uint8_t kblck[64];
  uint8_t mblck[64];

  DES::sttoblk( kblck, key );
  DES::sttoblk( mblck, msg );

  char dest[8] = {
    0, 0, 0, 0, 0, 0, 0, '\0'
  };

  for ( int i = 0; i < 1; i++ ) {
    DES cipher( mblck, kblck );
    cipher.encrypt();
    DES::blktostr( cipher.cipherText(), dest );
  }

  printf( "Cipher: ");

  for( int i = 0; i < 7; i++ ) {
    printf( "%c",(unsigned char) dest[i] );
  }

  return 0;
}
