
/**
 * Test suite
 */

#define UNITTEST 1

#include "des.hpp"
#include <stdint.h> 
#include <gtest/gtest.h>

using ::testing::InitGoogleTest;

TEST( DesBitOps, Get ) {
  ASSERT_TRUE(  des::get( 1, 0 ) );
  ASSERT_FALSE( des::get( 1, 1 ) );

  ASSERT_FALSE( des::get( 8, 0 ) );
  ASSERT_FALSE( des::get( 8, 1 ) );
  ASSERT_FALSE( des::get( 8, 2 ) );
  ASSERT_TRUE(  des::get( 8, 3 ) );
}

TEST( DesBitOps, On ) {

  uint8_t x = 0;
  des::on( &x, 0 );
  ASSERT_TRUE(  des::get( x, 0 ) );
  ASSERT_FALSE( des::get( x, 1 ) );
  ASSERT_FALSE( des::get( x, 2 ) );
  ASSERT_FALSE( des::get( x, 3 ) );
  ASSERT_FALSE( des::get( x, 4 ) );
  ASSERT_FALSE( des::get( x, 5 ) );
  ASSERT_FALSE( des::get( x, 6 ) );
  ASSERT_FALSE( des::get( x, 7 ) );

}

TEST( DesBitOps, Off ) {

  uint8_t x = 1;
  des::off( &x, 0 );
  ASSERT_FALSE( des::get( x, 0 ) );
  ASSERT_FALSE( des::get( x, 1 ) );
  ASSERT_FALSE( des::get( x, 2 ) );
  ASSERT_FALSE( des::get( x, 3 ) );
  ASSERT_FALSE( des::get( x, 4 ) );
  ASSERT_FALSE( des::get( x, 5 ) );
  ASSERT_FALSE( des::get( x, 6 ) );
  ASSERT_FALSE( des::get( x, 7 ) );

  uint8_t y = 8;
  des::off( &y, 3 );
  ASSERT_FALSE( des::get( y, 0 ) );
  ASSERT_FALSE( des::get( y, 1 ) );
  ASSERT_FALSE( des::get( y, 2 ) );
  ASSERT_FALSE( des::get( y, 3 ) );
  ASSERT_FALSE( des::get( y, 4 ) );
  ASSERT_FALSE( des::get( y, 5 ) );
  ASSERT_FALSE( des::get( y, 6 ) );
  ASSERT_FALSE( des::get( y, 7 ) );

}

TEST( DESAlgo, Encrypt ) {

  char key[17] = "133457799BBCDFF1";
  char msg[17] = "0123456789ABCDEF";

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

  char* ciphertext = "85E813540F0AB405";
  ASSERT_TRUE( strcmp( dest, ciphertext ) == 0 );
}


 
int main( int argc, char **argv ) {

  InitGoogleTest( &argc, argv );
  return RUN_ALL_TESTS();

}
