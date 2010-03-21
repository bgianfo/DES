/*
**
**  Authors:
** 
**     Sam Milton
**     Brian Gianforcaro (bjg1955@cs.rit.edu)
**
**
*/

#include <cstdio>
#include "stdint.h"

#include "des.hpp"

int main( int argc, char** argv ) {

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

  des cipher( mblck, kblck );
  cipher.encrypt();
  des::blktostr( cipher.cipherText(), dest );
  printf( "CipherText: %s\n", dest );
 
}
