/*
**
**  DES Test suite:
**
**  Authors:
**      Sam Milton        (srm2997@cs.rit.edu)
**      Brian Gianforcaro (bjg1955@cs.rit.edu)
**
*/

#define UNITTEST 1

#include "des.hpp"
#include <stdint.h>
#include <gtest/gtest.h>

#ifndef  GTEST_INCLUDE_GTEST_GTEST_H_
 #error Google testing framework required
#endif

using ::testing::InitGoogleTest;

TEST( f_function, Test ){
  uint8_t dum[64];
  DES dummy( dum, dum );

  uint8_t ans[32] = { 0,0,1,0,0,0,1,1,0,1,0,0,1,0,1,0,1,0,1,0,1,0,0,1,1,0,1,1,1,0,1,1 };
  uint8_t dest[32];
  uint8_t R[48] = { 1,1,1,1,0,0,0,0,1,0,1,0,1,0,1,0,1,1,1,1,0,0,0,0,1,0,1,0,1,0,1,0 };
  uint8_t K[48] = {0,0,0,1,1,0,1,1,0,0,0,0,0,0,1,0,1,1,1,0,1,1,1,1,1,1,1,1,1,1,0,0,0,1,1,1,0,0,0,0,0,1,1,1,0,0,1,0};

  dummy.f( dest, R, K );

  for( int i = 0; i < 32; ++i ){
    ASSERT_TRUE( dest[i] == ans[i] );
  }

}

TEST( Keygen, match ) {

  uint8_t msg[64] = { 0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,
                      0,1,1,0,0,1,1,1,1,0,0,0,1,0,0,1,1,0,1,0,1,0,1,1,
                      1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1 };

  uint8_t key[64] = { 0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,0,0,0,1};

  uint8_t correct_keys[16][48] = {
    { 0,0,0,1,1,0,1,1,0,0,0,0,0,0,1,0,1,1,1,0,1,1,1,1,1,1,1,1,1,1,0,0,0,1,1,1,0,0,0,0,0,1,1,1,0,0,1,0 },
    { 0,1,1,1,1,0,0,1,1,0,1,0,1,1,1,0,1,1,0,1,1,0,0,1,1,1,0,1,1,0,1,1,1,1,0,0,1,0,0,1,1,1,1,0,0,1,0,1 },
    { 0,1,0,1,0,1,0,1,1,1,1,1,1,1,0,0,1,0,0,0,1,0,1,0,0,1,0,0,0,0,1,0,1,1,0,0,1,1,1,1,1,0,0,1,1,0,0,1 },
    { 0,1,1,1,0,0,1,0,1,0,1,0,1,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,1,0,1,1,0,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1 },
    { 0,1,1,1,1,1,0,0,1,1,1,0,1,1,0,0,0,0,0,0,0,1,1,1,1,1,1,0,1,0,1,1,0,1,0,1,0,0,1,1,1,0,1,0,1,0,0,0 },
    { 0,1,1,0,0,0,1,1,1,0,1,0,0,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,0,0,0,0,0,1,1,1,1,0,1,1,0,0,1,0,1,1,1,1 },
    { 1,1,1,0,1,1,0,0,1,0,0,0,0,1,0,0,1,0,1,1,0,1,1,1,1,1,1,1,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,0 },
    { 1,1,1,1,0,1,1,1,1,0,0,0,1,0,1,0,0,0,1,1,1,0,1,0,1,1,0,0,0,0,0,1,0,0,1,1,1,0,1,1,1,1,1,1,1,0,1,1 },
    { 1,1,1,0,0,0,0,0,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,1,1,1,1,0,0,1,1,1,1,0,0,0,0,0,0,1 },
    { 1,0,1,1,0,0,0,1,1,1,1,1,0,0,1,1,0,1,0,0,0,1,1,1,1,0,1,1,1,0,1,0,0,1,0,0,0,1,1,0,0,1,0,0,1,1,1,1 },
    { 0,0,1,0,0,0,0,1,0,1,0,1,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,1,1,1,0,1,1,0,1,0,0,1,1,1,0,0,0,0,1,1,0 },
    { 0,1,1,1,0,1,0,1,0,1,1,1,0,0,0,1,1,1,1,1,0,1,0,1,1,0,0,1,0,1,0,0,0,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1 },
    { 1,0,0,1,0,1,1,1,1,1,0,0,0,1,0,1,1,1,0,1,0,0,0,1,1,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,0,1,0,0,0,0,0,1 },
    { 0,1,0,1,1,1,1,1,0,1,0,0,0,0,1,1,1,0,1,1,0,1,1,1,1,1,1,1,0,0,1,0,1,1,1,0,0,1,1,1,0,0,1,1,1,0,1,0 },
    { 1,0,1,1,1,1,1,1,1,0,0,1,0,0,0,1,1,0,0,0,1,1,0,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,1,1,0,0,0,0,1,0,1,0 },
    { 1,1,0,0,1,0,1,1,0,0,1,1,1,1,0,1,1,0,0,0,1,0,1,1,0,0,0,0,1,1,1,0,0,0,0,1,0,1,1,1,1,1,1,1,0,1,0,1 }
  };

  DES cipher( msg, key );
  cipher.keyschedule();

  for ( int i = 0; i < ROUNDS; i++ ) {
    for ( int j = 0; j < 48; j++ ) {
      EXPECT_EQ( cipher.scheduled_keys[i][j] , correct_keys[i][j] );
    }
  }

}


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

  char msg[9] = "01234567";

  uint8_t expected[] = {0,0,1,1,0,0,0,0,0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,0,0,0,1,1,0,0,1,1,0,0,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,1,1,0,1,1,0,0,0,1,1,0,1,1,1};

  uint8_t* output1 = new uint8_t[64];

  DES::sttoblk( output1, msg );

  for (int i = 0; i < 8; i++ ) {
    ASSERT_TRUE( expected[i] == output1[i] );
  }


}

TEST( DESutil, blktostr ) {
  char expected[9] = "01234567";

  uint8_t in[] = {0,0,1,1,0,0,0,0,0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,0,0,0,1,1,0,0,1,1,0,0,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,1,1,0,1,1,0,0,0,1,1,0,1,1,1};

  char outmsg[8];

  DES::blktostr( in, outmsg );

  for (int i = 0; i < 8; i++ ) {
    ASSERT_TRUE( expected[i] == outmsg[i] );
  }
}

TEST( DESAlgo, Encrypt ) {

  uint8_t msg[64] = { 0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,
                      0,1,1,0,0,1,1,1,1,0,0,0,1,0,0,1,1,0,1,0,1,0,1,1,
                      1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1 };

  uint8_t key[64] = { 0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,0,0,0,1};

  DES cipher( msg, key );

  cipher.encrypt();

  uint8_t ciphertext[64] = { 1,0,0,0,0,1,0,1,1,1,1,0,1,0,0,0,0,0,0,1,0,0,1,1,0,1,0,1,0,1,0,0,0,0,0,0,1,1,1,1,0,0,0,0,1,0,1,0,1,0,1,1,0,1,0,0,0,0,0,0,0,1,0,1 };

  for( int i = 0; i < 64; i++ ) {
      EXPECT_EQ( ciphertext[i], cipher.cipherText()[i] );
  }

}

TEST( DESAlgo, Decrypt ) {
  uint8_t ciphertext[64] = { 1,0,0,0,0,1,0,1,1,1,1,0,1,0,0,0,0,0,0,1,0,0,1,1,0,1,0,1,0,1,0,0,0,0,0,0,1,1,1,1,0,0,0,0,1,0,1,0,1,0,1,1,0,1,0,0,0,0,0,0,0,1,0,1 };

  uint8_t key[64] = { 0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,0,0,0,1};

  DES cipher( ciphertext, key );

  cipher.decrypt();

  uint8_t msg[64] = { 0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,
                      0,1,1,0,0,1,1,1,1,0,0,0,1,0,0,1,1,0,1,0,1,0,1,1,
                      1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1 };

  for( int i = 0; i < 64; i++ ) {
    EXPECT_EQ( msg[i], cipher.plainText()[i] );
  }

}


int main( int argc, char **argv ) {

  InitGoogleTest( &argc, argv );
  return RUN_ALL_TESTS();

}
