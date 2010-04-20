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

  char key[17] = "133457799BBCDFF1";
  char msg[17] = "0123456789ABCDEF";

  printf( "Encrypting: %s\n", msg );
  printf( "With Key: %s\n", key );

  uint8_t kblck[64];
  uint8_t mblck[64];

  des::sttoblk( kblck, key );
  des::sttoblk( mblck, msg );

  char dest[17] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, '\0'
  };

  for ( int i = 0; i < 1000000; i++ ) {
    des cipher( mblck, kblck );
    cipher.encrypt();
    des::blktostr( cipher.cipherText(), dest );
  }

  printf( "With Key: ");

  for( int i = 0; i < strlen(dest); i++ ) {
    printf( "%x", dest[i] );
  }

  return 0;
}
