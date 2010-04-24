
/**
 * Test suite
 */

#define UNITTEST 1

#include "des.hpp"
#include <stdint.h>
#include <gtest/gtest.h>

using ::testing::InitGoogleTest;

TEST( DesBitOps, Get ) {
  ASSERT_TRUE(  DES::get( 1, 0 ) );
  ASSERT_FALSE( DES::get( 1, 1 ) );

  ASSERT_FALSE( DES::get( 8, 0 ) );
  ASSERT_FALSE( DES::get( 8, 1 ) );
  ASSERT_FALSE( DES::get( 8, 2 ) );
  ASSERT_TRUE(  DES::get( 8, 3 ) );
}

TEST( DesBitOps, On ) {

  uint8_t x = 0;
  DES::on( &x, 0 );
  ASSERT_TRUE(  DES::get( x, 0 ) );
  ASSERT_FALSE( DES::get( x, 1 ) );
  ASSERT_FALSE( DES::get( x, 2 ) );
  ASSERT_FALSE( DES::get( x, 3 ) );
  ASSERT_FALSE( DES::get( x, 4 ) );
  ASSERT_FALSE( DES::get( x, 5 ) );
  ASSERT_FALSE( DES::get( x, 6 ) );
  ASSERT_FALSE( DES::get( x, 7 ) );

  x = 0;
  DES::on( &x, 3 );
  ASSERT_FALSE(  DES::get( x, 0 ) );
  ASSERT_FALSE( DES::get( x, 1 ) );
  ASSERT_FALSE( DES::get( x, 2 ) );
  ASSERT_TRUE( DES::get( x, 3 ) );
  ASSERT_FALSE( DES::get( x, 4 ) );
  ASSERT_FALSE( DES::get( x, 5 ) );
  ASSERT_FALSE( DES::get( x, 6 ) );
  ASSERT_FALSE( DES::get( x, 7 ) );


}

TEST( DesBitOps, Off ) {

  uint8_t x = 1;
  DES::off( &x, 0 );
  ASSERT_FALSE( DES::get( x, 0 ) );
  ASSERT_FALSE( DES::get( x, 1 ) );
  ASSERT_FALSE( DES::get( x, 2 ) );
  ASSERT_FALSE( DES::get( x, 3 ) );
  ASSERT_FALSE( DES::get( x, 4 ) );
  ASSERT_FALSE( DES::get( x, 5 ) );
  ASSERT_FALSE( DES::get( x, 6 ) );
  ASSERT_FALSE( DES::get( x, 7 ) );

  uint8_t y = 8;
  DES::off( &y, 3 );
  ASSERT_FALSE( DES::get( y, 0 ) );
  ASSERT_FALSE( DES::get( y, 1 ) );
  ASSERT_FALSE( DES::get( y, 2 ) );
  ASSERT_FALSE( DES::get( y, 3 ) );
  ASSERT_FALSE( DES::get( y, 4 ) );
  ASSERT_FALSE( DES::get( y, 5 ) );
  ASSERT_FALSE( DES::get( y, 6 ) );
  ASSERT_FALSE( DES::get( y, 7 ) );

}

TEST( DESutil, strtoblk ) {

  char *msg = "0123456";

  block_t output1 = new uint8_t[56];

  DES::sttoblk( output1, msg );

  char outmsg[8];
  outmsg[8] = '\0';

  memset(outmsg, 0, 8 );

  DES::blktostr( output1, outmsg );

  for (int i = 0; i < 7; i++ ) {
    ASSERT_TRUE( outmsg[i] == msg[i] );
  }


}

TEST( DESAlgo, Encrypt ) {

  char key[8] = "0123456"; 
  char msg[8] = "0123456";

  uint8_t kblck[64];
  uint8_t mblck[64];

  DES::sttoblk( kblck, key );
  DES::sttoblk( mblck, msg );

  char dest[8] = {
    0, 0, 0, 0, 0, 0, 0, 0,
  };

  DES cipher( mblck, kblck );
  cipher.encrypt();
  DES::blktostr( cipher.cipherText(), dest );

  char ciphertext[] = {
    0x66,0x27,0x01,0x97,0x92,0x4E,0x36,0x2E
  };
  /*
  char ciphertext[] = "85E813540F0AB405";
  */

  for( int i = 0; i < 8; i++ ) {
      printf("%02X  == %02X\n", (unsigned char)dest[i] , (unsigned char)ciphertext[i] );
  }
  for( int i = 0; i < 8; i++ ) {
      ASSERT_TRUE( dest[i] == ciphertext[i] );
  }

}

int main( int argc, char **argv ) {

  InitGoogleTest( &argc, argv );
  return RUN_ALL_TESTS();

}
