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
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <stdint.h>

#include "des.hpp"

/* Shift's change depending on which round we are on */
unsigned char des::SHIFTS[ROUNDS] = {
  1, 1, 2, 2,
  2, 2, 2, 2,
  1, 2, 2, 2, 
  2, 2, 2 ,1
};

/* Primative functino P pg: 22 of DES spec */
unsigned char des::P[32] = {
  16,  7, 20, 21,
  29, 12, 28, 17,
   1, 15, 23, 26,
   5, 18, 31, 10,
   2,  8, 24, 14,
  32, 27,  3,  9,
  19, 13, 30,  6,
  22, 11,  4, 25 
};

unsigned char des::E[48] = {
  32,  1,  2,  3,  4,  5, 
   4,  5,  6,  7,  8,  9, 
   8,  9, 10, 11, 12, 13, 
  12, 13, 14, 15, 16, 17, 
  16, 17, 18, 19, 20, 21, 
  20, 21, 22, 23, 24, 25, 
  24, 25, 26, 27, 28, 29, 
  28, 29, 30, 31, 32,  1
};

/* Permiated choice #1 pg: 23 of DES spec */
unsigned char des::PC1[56] = {
  57, 49, 41, 33, 25, 17,  9,
   1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27,
  19, 11,  3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
   7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29,
  21, 13,  5, 28, 20, 12,  4
};

unsigned char des::PC2[56] = {

};

/* IP prime pg: 14 */
unsigned char des::IP[64] = {
  58, 50, 42, 34, 26, 18, 10, 2, 
  60, 52, 44, 36, 28, 20, 12, 4, 
  62, 54, 46, 38, 30, 22, 14, 6, 
  64, 56, 48, 40, 32, 24, 16, 8, 
  57, 49, 41, 33, 25, 17,  9, 1, 
  59, 51, 43, 35, 27, 19, 11, 3, 
  61, 53, 45, 37, 29, 21, 13, 5, 
  63, 55, 47, 39, 31, 23, 15, 7 
};

/* IP prime pg: 14 */
unsigned char des::IPP[64] = {
  40,  8, 48, 16, 56, 24, 64, 32, 
  39,  7, 47, 15, 55, 23, 63, 31, 
  38,  6, 46, 14, 54, 22, 62, 30, 
  37,  5, 45, 13, 53, 21, 61, 29, 
  36,  4, 44, 12, 52, 20, 60, 28, 
  35,  3, 43, 11, 51, 19, 59, 27, 
  34,  2, 42, 10, 50, 18, 58, 26, 
  33,  1, 41,  9, 49, 17, 57, 25
};

/* All S-Boxes  */
unsigned char des::SP[8][4][16] = {

  /* S1 function pg: 19 of DES spec */
  {
    { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7 },
    {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8 },
    {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0 },
    { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13 }
  },

  /* S2 function pg: 19 of DES spec */
  { 
    { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
    {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
    {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
    { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
  },

  /* S3 function pg: 19 of DES spec */
  {
    { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
    { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
    { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
    {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
  },

  /* S4 function pg: 19 of DES spec */
  {
    {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
    { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
    { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
    {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
  },

  /* S5 function pg: 20 of DES spec */
  {
    {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
    { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
    {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
    { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
  },

  /* S6 function pg: 20 of DES spec */
  {
    { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
    { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
    {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
    {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
  },

  /* S7 function pg: 20 of DES spec */
  {
    {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
    { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
    {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
    {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
  },

  /* S8 function pg: 20 of DES spec */
  {
    { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
    {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
    {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
    {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
  }

};


/**
 * @param block, 64 bit data block made up of two 32bit int's
 * @param key, 64 bit key made up of two 32bit int's
 */
des::des( uint8_t* block , uint8_t * key ) {

  assert( block != NULL );
  assert( key != NULL );

  this->block = new uint8_t[8];
  this->key = new uint8_t[8];

  for ( int i = 0; i < 8; i++ ) {
    this->block[i] = block[i];
    this->key[i] = key[i];
  }

  this->rounds = 0;
}

des::~des( ) {
  delete this->block;
  delete this->key;
}

/* 
**  Key schedule:
**
**   C[0]D[0] = PC1(key)
**   for 1 <= i <= 16
**      C[i] = LS[i](C[i-1])
**      D[i] = LS[i](D[i-1])
**      K[i] = PC2(C[i]D[i])
**
*/
void des::keyschedule( void ) {

}

/*
**
** Encipherment:
**
**   L[0]R[0] = IP(plain block)
**   for 1 <= i <= 16
**      L[i] = R[i-1]
**      R[i] = L[i-1] xor f(R[i-1], K[i])
**      cipher block = FP(R[16]L[16])
**
** Implements the main enciphering algorithm in figure 1 pg: 13 DES spec
**
*/
void des::encrypt() {

  assert( rounds == 0 or rounds >= 15 );

  permiate();

  for( unsigned int i = 0; i <= ROUNDS; i++ ) {

  }

  inv_permiate();
  return;
}

/**
 *
 */
bool des::get( uint8_t data, int bit ) {
  int mask = 1 << bit;
  return data & mask;
}

/**
 * Turn a specific bit of "data" on.
 *
 * @data - pointer of the byte to operate on.
 * @bit - nth bit to modify.
 */

void des::on( uint8_t* data, const int bit ) {
  *data |= (1 << bit);
}

/**
 * Turn a specific bit of "data" off.
 *
 * @data - pointer of the byte to operate on.
 * @bit - nth bit to modify.
 */

void des::off( uint8_t* data, const int bit ) {
  *data &= ~(1 << bit);
}

/**
 * Decipherment:
 *
 *   R[16]L[16] = IP(cipher block)
 *   for 1 <= i <= 16
 *     R[i-1] = L[i]
 *     L[i-1] = R[i] xor f(L[i], K[i])
 *     plain block = FP(L[0]R[0])
 */

void des::decrypt() {

  char L[16];
  char R[16];
  for( unsigned int i = 0; i <= ROUNDS; i++ ) {

  }

}

/**
 *
 * @param R is 32 bit chunk of block
 * @param K is 48 bit chunk of the key.
 *
 */
void des::f( char* R, char* K ) {

}

/*
**
** Scramble the plain text a little bit.
**
*/
void des::permiate( void ) {
  assert( block != NULL );
  assert( this->rounds == 0 );


  uint8_t* n_block = new uint8_t[8];
  memset( n_block, 0, 8 );

  for( uint8_t i = 0; i < BKSIZE; i++ ) {
    if ( des::get( this->block[i/8], (IP[i]/8 - 1) ) ) {
      des::on( &(n_block[i/8]), (IP[i]/8 - 1) );
    }
  }

  delete this->block;
  this->block = n_block;
  return;
}

/*
**
** Inverse scramble the plain text a little bit.
**
*/
void des::inv_permiate( void ) {

  assert( block != NULL );
  assert( this->rounds >= 15 );

  uint8_t* n_block = new uint8_t[8];
  memset( n_block, 0, 8 );

  for( uint8_t i = 0; i < BKSIZE; i++ ) {
    if ( des::get( this->block[i/8], (IPP[i]/8 - 1) ) ) {
      des::on( &(n_block[i/8]), (IPP[i]/8 - 1) );
    }
  }

  delete this->block;
  this->block = n_block;
  return;

  for( unsigned int i = 0; i < BKSIZE; i++ ) {
    this->block[i] = this->block[ IPP[i] - 1 ];
  }
  return;
}
