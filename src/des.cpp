/*
**  File: des.cpp
**
**  Authors:
**
**     Sam Milton        (srm2997@rit.edu)
**     Brian Gianforcaro (bjg1955@cs.rit.edu)
**
**  Description:
**
**     This initial implementation of the DES spec uses array's of 8-bit int's with
**     64 elements each to represent both the DES block and DES key.
**     Each element in the array is considered to be a single bit, and is either 0 or 1.
*/


#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <stdint.h>
#include <algorithm>

#include "des.hpp"

using namespace std;

/*
**
** Default Constructor
**
** @param block, 64 bit data block made up of two 32bit int's
** @param key, 64 bit key made up of two 32bit int's
**
*/

DES::DES( uint8_t* block , uint8_t* key ) {

  assert( block != NULL );
  assert( key != NULL );

  this->block = new uint8_t[BKSIZE];
  this->key = new uint8_t[BKSIZE];

  memcpy( this->block, block, BKSIZE );
  memcpy( this->key, key, BKSIZE );
  this->round = 0;

  this->ciphertext = NULL;
  this->plaintext  = NULL;
}

/*
** Default Destructor
*/

DES::~DES( void ) {

  delete[] this->block;
  delete[] this->key;

  if ( this->ciphertext != NULL ) {
    delete[] this->ciphertext;
  }

  if ( this->plaintext != NULL ) {
    delete[] this->plaintext;
  }
}

/*
** Public API to encryption algorithm of the class.
**
** Encipherment:
**
**   L[0]R[0] = IP(plain block)
**   for 1 <= i <= 16
**      L[i] = R[i-1]
**      R[i] = L[i-1] xor f(R[i-1], K[i])
**      cipher block = FP(R[16]L[16])
*/

void DES::encrypt( void ) {
  assert( round == 0 or round >= 15 );
  this->ciphertext = new uint8_t[BKSIZE];
  this->algorithm( encrypt_a );
}

/*
** Public API to decryption algorithm of the class.
**
** Decipherment:
**
**   R[16]L[16] = IP(cipher block)
**   for 1 <= i <= 16
**     R[i-1] = L[i]
**     L[i-1] = R[i] xor f(L[i], K[i])
**     plain block = FP(L[0]R[0])
*/

void DES::decrypt( void ) {
  assert( round == 0 or round >= 15 );
  this->plaintext = new uint8_t[BKSIZE];
  this->algorithm( decrypt_a );
}




/* Init Permuatation Definition:
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,

  57, 49, 41, 33, 25, 17,  9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7
*/
void DES::initPermutation( uint8_t block[], uint8_t out[] ){
  out[0]  = block[57];  out[1]  = block[49];
  out[2]  = block[41];  out[3]  = block[33];
  out[4]  = block[25];  out[5]  = block[17];
  out[6]  = block[9];   out[7]  = block[1];
  out[8]  = block[59];  out[9]  = block[51];
  out[10] = block[43];  out[11] = block[35];
  out[12] = block[27];  out[13] = block[19];
  out[14] = block[11];  out[15] = block[3];
  out[16] = block[61];  out[17] = block[53];
  out[18] = block[45];  out[19] = block[37];
  out[20] = block[29];  out[21] = block[21];
  out[22] = block[13];  out[23] = block[5];
  out[24] = block[63];  out[25] = block[55];
  out[26] = block[47];  out[27] = block[39];
  out[28] = block[31];  out[29] = block[23];
  out[30] = block[15];  out[31] = block[7];
  out[32] = block[56];  out[33] = block[48];
  out[34] = block[40];  out[35] = block[32];
  out[36] = block[24];  out[37] = block[16];
  out[38] = block[8];   out[39] = block[0];
  out[40] = block[58];  out[41] = block[50];
  out[42] = block[42];  out[43] = block[34];
  out[44] = block[26];  out[45] = block[18];
  out[46] = block[10];  out[47] = block[2];
  out[48] = block[60];  out[49] = block[52];
  out[50] = block[44];  out[51] = block[36];
  out[52] = block[28];  out[53] = block[20];
  out[54] = block[12];  out[55] = block[4];
  out[56] = block[62];  out[57] = block[54];
  out[58] = block[46];  out[59] = block[38];
  out[60] = block[30];  out[61] = block[22];
  out[62] = block[14];  out[63] = block[6];
}


/*
  Primative Definition
  16,  7, 20, 21,
  29, 12, 28, 17,
   1, 15, 23, 26,
   5, 18, 31, 10,

   2,  8, 24, 14,
  32, 27,  3,  9,
  19, 13, 30,  6,
  22, 11,  4, 25
*/
void DES::primative( uint8_t block[], uint8_t out[] ) {

}


/* Inverse Init Permutation Definition:

*/
void DES::inverseInitPermutation( uint8_t block[], uint8_t out[] ) {

  out[0]   =  block[39];  out[1]   =  block[ 7];
  out[2]   =  block[47];  out[3]   =  block[15];
  out[4]   =  block[55];  out[5]   =  block[23];
  out[6]   =  block[63];  out[7]   =  block[31];
  out[8]   =  block[38];  out[9]   =  block[ 6];
  out[10]  =  block[46];  out[11]  =  block[14];
  out[12]  =  block[54];  out[13]  =  block[22];
  out[14]  =  block[62];  out[15]  =  block[30];
  out[16]  =  block[37];  out[17]  =  block[ 5];
  out[18]  =  block[45];  out[19]  =  block[13];
  out[20]  =  block[53];  out[21]  =  block[21];
  out[22]  =  block[61];  out[23]  =  block[29];
  out[24]  =  block[36];  out[25]  =  block[ 4];
  out[26]  =  block[44];  out[27]  =  block[12];
  out[28]  =  block[52];  out[29]  =  block[20];
  out[30]  =  block[60];  out[31]  =  block[28];
  out[32]  =  block[35];  out[33]  =  block[ 3];
  out[34]  =  block[43];  out[35]  =  block[11];
  out[36]  =  block[51];  out[37]  =  block[19];
  out[38]  =  block[59];  out[39]  =  block[27];
  out[40]  =  block[34];  out[41]  =  block[ 2];
  out[42]  =  block[42];  out[43]  =  block[10];
  out[44]  =  block[50];  out[45]  =  block[18];
  out[46]  =  block[58];  out[47]  =  block[26];
  out[48]  =  block[33];  out[49]  =  block[ 1];
  out[50]  =  block[41];  out[51]  =  block[ 9];
  out[52]  =  block[49];  out[53]  =  block[17];
  out[54]  =  block[57];  out[55]  =  block[25];
  out[56]  =  block[32];  out[57]  =  block[ 0];
  out[58]  =  block[40];  out[59]  =  block[ 8];
  out[60]  =  block[48];  out[61]  =  block[16];
  out[62]  =  block[56];  out[63]  =  block[24];

}


/*
**
** Implements the main enciphering algorithm in figure 1 pg: 13 DES spec
**
*/

void DES::algorithm( const action_t action ) {

  /* Schedule them key's! */
  this->keyschedule();

  uint8_t tmp[BKSIZE];

  /* Mix up the input data block a little bit */
  this->initPermutation( this->block, tmp );

  /* Split the input data block */
  block_t l = tmp;
  block_t r = tmp + (BKSIZE/2);

  for ( this->round = 0; this->round < ROUNDS; this->round++ ) {

    uint8_t* key;
    if ( action == encrypt_a ) {
      key = this->scheduled_keys[ this->round ];
    } else {
      key = this->scheduled_keys[ ( ROUNDS - 1 )  - this->round ];
    }

    /* store r for later */
    uint8_t r_saved[(BKSIZE/2)];
    memcpy( r_saved, r, BKSIZE/2 );

    /* Run the Fiestel function */
    uint8_t fblck[32];
    DES::f( fblck, r, key );

    /* R = L ^ f(R,K) */
    for ( int j = 0; j < 32; j++ ) {
      r[j] =  l[j] ^ fblck[j];
    }

    /* Swap l and saved r for the next round */
    memcpy( l, r_saved, BKSIZE/2 );
  }

  /* Swap output before final permutation */
  std::swap_ranges( l, l + (BKSIZE/2), r );

  /*
  ** Copy result back into destination,
  ** remember l and r point to separate
  ** halves of a continuous block of size 64.
  */
  this->inverseInitPermutation( l, (action == encrypt_a) ? this->ciphertext : this->plaintext );
}

/* All S-Boxes  */
uint8_t DES::SP[8][4][16] =
{
  {
     /* S1 function pg: 19 of DES spec */
      { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7},
      {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8},
      {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0},
      { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13}

  },{
     /* S2 function pg: 19 of DES spec */
     {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
     { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
     { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
     {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
  },{
     /* S3 function pg: 19 of DES spec */
     {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
     {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
     {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
     { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
  },{
     /* S4 function pg: 19 of DES spec */
     { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
     {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
     {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
     { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
  },{
     /* S5 function pg: 20 of DES spec */
     { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
     {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
     { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
     {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
  },{
  /* S6 function pg: 20 of DES spec */
     {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
     {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
     { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
     { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
  },{
     /* S7 function pg: 20 of DES spec */
     { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
     {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
     { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
     { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
  },{
     /* S8 function pg: 20 of DES spec */
     {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
     { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
     { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
     { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
  }
};

/*
** DES Fiestel function
**
** @param dest is 32 bit chunk of block
** @param R is 32 bit chunk of block
** @param K is 48 bit chunk of the key.
**
** @note input size is 2 48 bits blocks output is one 32 bit block.
*/

void DES::f( block_t dest, block_t R, block_t K ) {

  /* clear dest */
  memset( dest, 0, (BKSIZE/2) );

  /* Expand left side to 48 bits to match key */
  uint8_t rpk[48];

  // Expand function
  rpk[0] = R[31] ^ K[0];   rpk[1] = R[0] ^ K[1];  
  rpk[2] = R[1] ^ K[2];    rpk[3] = R[2] ^ K[3];  
  rpk[4] = R[3] ^ K[4];    rpk[5] = R[4] ^ K[5];  
  rpk[6] = R[3] ^ K[6];    rpk[7] = R[4] ^ K[7];  
  rpk[8] = R[5] ^ K[8];    rpk[9] = R[6] ^ K[9];  
  rpk[10] = R[7] ^ K[10];  rpk[11] = R[8] ^ K[11]; 
  rpk[12] = R[7] ^ K[12];  rpk[13] = R[8] ^ K[13]; 
  rpk[14] = R[9] ^ K[14];  rpk[15] = R[10] ^ K[15];
  rpk[16] = R[11] ^ K[16]; rpk[17] = R[12] ^ K[17];
  rpk[18] = R[11] ^ K[18]; rpk[19] = R[12] ^ K[19];
  rpk[20] = R[13] ^ K[20]; rpk[21] = R[14] ^ K[21];
  rpk[22] = R[15] ^ K[22]; rpk[23] = R[16] ^ K[23];
  rpk[24] = R[15] ^ K[24]; rpk[25] = R[16] ^ K[25];
  rpk[26] = R[17] ^ K[26]; rpk[27] = R[18] ^ K[27];
  rpk[28] = R[19] ^ K[28]; rpk[29] = R[20] ^ K[29];
  rpk[30] = R[19] ^ K[30]; rpk[31] = R[20] ^ K[31];
  rpk[32] = R[21] ^ K[32]; rpk[33] = R[22] ^ K[33];
  rpk[34] = R[23] ^ K[34]; rpk[35] = R[24] ^ K[35];
  rpk[36] = R[23] ^ K[36]; rpk[37] = R[24] ^ K[37];
  rpk[38] = R[25] ^ K[38]; rpk[39] = R[26] ^ K[39];
  rpk[40] = R[27] ^ K[40]; rpk[41] = R[28] ^ K[41];
  rpk[42] = R[27] ^ K[42]; rpk[43] = R[28] ^ K[43];
  rpk[44] = R[29] ^ K[44]; rpk[45] = R[30] ^ K[45];
  rpk[46] = R[31] ^ K[46]; rpk[47] = R[0] ^ K[47];
  // End Expand function

  for( int i = 0; i < 8; ++i ){
    /* Identify block of rpk (each block is 6 bits) */
    uint8_t block = i * 6;
    /* Bits 0 and 5 make index m */
    uint8_t m = rpk[block] * 2 + rpk[block + 5];
    /* Bits 1-4 make index n */
    uint8_t n = rpk[block + 1] * 8 + rpk[block + 2] * 4 + rpk[block + 3] * 2 + rpk[block + 4];

    /* Index from the S-Functions and store resulting bits into the answer */
    rpk[i*4] = (bool)(SP[i][m][n] & 8);
    rpk[i*4+1] = (bool)(SP[i][m][n] & 4);
    rpk[i*4+2] = (bool)(SP[i][m][n] & 2);
    rpk[i*4+3] = (bool)(SP[i][m][n] & 1);
  }

  // Primitive Function
  dest[0]  = rpk[15];  dest[1]  = rpk[6];
  dest[2]  = rpk[19];  dest[3]  = rpk[20];
  dest[4]  = rpk[28];  dest[5]  = rpk[11];
  dest[6]  = rpk[27];  dest[7]  = rpk[16];
  dest[8]  = rpk[0];   dest[9]  = rpk[14];
  dest[10] = rpk[22];  dest[11] = rpk[25];
  dest[12] = rpk[4];   dest[13] = rpk[17];
  dest[14] = rpk[30];  dest[15] = rpk[9];
  dest[16] = rpk[1];   dest[17] = rpk[7];
  dest[18] = rpk[23];  dest[19] = rpk[13];
  dest[20] = rpk[31];  dest[21] = rpk[26];
  dest[22] = rpk[2];   dest[23] = rpk[8];
  dest[24] = rpk[18];  dest[25] = rpk[12];
  dest[26] = rpk[29];  dest[27] = rpk[5];
  dest[28] = rpk[21];  dest[29] = rpk[10];
  dest[30] = rpk[3];   dest[31] = rpk[24];
  // End Primitive Function
}


/* Shift's change depending on which round we are on */
uint8_t DES::SHIFTS[ROUNDS] =
{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };


/* Permutation One Definition
  57, 49, 41, 33, 25, 17,  9,
   1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27,
  19, 11,  3, 60, 52, 44, 36,

  63, 55, 47, 39, 31, 23, 15,
   7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29,
  21, 13,  5, 28, 20, 12,  4,
*/
void DES::permutation_one( uint8_t key[], uint8_t out[] ) {

   out[0]   =  key[56];   out[1]   =  key[48];
   out[2]   =  key[40];   out[3]   =  key[32];
   out[4]   =  key[24];   out[5]   =  key[16];
   out[6]   =  key[ 8];   out[7]   =  key[ 0];
   out[8]   =  key[57];   out[9]   =  key[49];
   out[10]  =  key[41];   out[11]  =  key[33];
   out[12]  =  key[25];   out[13]  =  key[17];
   out[14]  =  key[ 9];   out[15]  =  key[ 1];
   out[16]  =  key[58];   out[17]  =  key[50];
   out[18]  =  key[42];   out[19]  =  key[34];
   out[20]  =  key[26];   out[21]  =  key[18];
   out[22]  =  key[10];   out[23]  =  key[ 2];
   out[24]  =  key[59];   out[25]  =  key[51];
   out[26]  =  key[43];   out[27]  =  key[35];
   out[28]  =  key[62];   out[29]  =  key[54];
   out[30]  =  key[46];   out[31]  =  key[38];
   out[32]  =  key[30];   out[33]  =  key[22];
   out[34]  =  key[14];   out[35]  =  key[ 6];
   out[36]  =  key[61];   out[37]  =  key[53];
   out[38]  =  key[45];   out[39]  =  key[37];
   out[40]  =  key[29];   out[41]  =  key[21];
   out[42]  =  key[13];   out[43]  =  key[ 5];
   out[44]  =  key[60];   out[45]  =  key[52];
   out[46]  =  key[44];   out[47]  =  key[36];
   out[48]  =  key[28];   out[49]  =  key[20];
   out[50]  =  key[12];   out[51]  =  key[ 4];
   out[52]  =  key[27];   out[53]  =  key[19];
   out[54]  =  key[11];   out[55]  =  key[ 3];
}


/* Permutation Two Definition
  14, 17, 11, 24,  1,  5,
   3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8,
  16,  7, 27, 20, 13,  2,

  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
*/
void DES::permutation_two( uint8_t key[], uint8_t out[] ) {

   out[0]   =  key[13];   out[1]   =  key[16];
   out[2]   =  key[10];   out[3]   =  key[23];
   out[4]   =  key[0];    out[5]   =  key[4]; 
   out[6]   =  key[2];    out[7]   =  key[27];
   out[8]   =  key[14];   out[9]   =  key[5]; 
   out[10]  =  key[20];   out[11]  =  key[9]; 
   out[12]  =  key[22];   out[13]  =  key[18];
   out[14]  =  key[11];   out[15]  =  key[3]; 
   out[16]  =  key[25];   out[17]  =  key[7]; 
   out[18]  =  key[15];   out[19]  =  key[6]; 
   out[20]  =  key[26];   out[21]  =  key[19];
   out[22]  =  key[12];   out[23]  =  key[1]; 
   out[24]  =  key[40];   out[25]  =  key[51];
   out[26]  =  key[30];   out[27]  =  key[36];
   out[28]  =  key[46];   out[29]  =  key[54];
   out[30]  =  key[29];   out[31]  =  key[39];
   out[32]  =  key[50];   out[33]  =  key[44];
   out[34]  =  key[32];   out[35]  =  key[47];
   out[36]  =  key[43];   out[37]  =  key[48];
   out[38]  =  key[38];   out[39]  =  key[55];
   out[40]  =  key[33];   out[41]  =  key[52];
   out[42]  =  key[45];   out[43]  =  key[41];
   out[44]  =  key[49];   out[45]  =  key[35];
   out[46]  =  key[28];   out[47]  =  key[31];
}


void DES::keyschedule( void ) {

  uint8_t C[56];
  uint8_t *D = C + 28;

  /*
  ** Generate both halves of the permutation on the key.
  ** Discarding the lowest order bit of every byte.
  */


   // Permutation One
   C[0]   =  key[56];   C[1]   =  key[48];
   C[2]   =  key[40];   C[3]   =  key[32];
   C[4]   =  key[24];   C[5]   =  key[16];
   C[6]   =  key[ 8];   C[7]   =  key[ 0];
   C[8]   =  key[57];   C[9]   =  key[49];
   C[10]  =  key[41];   C[11]  =  key[33];
   C[12]  =  key[25];   C[13]  =  key[17];
   C[14]  =  key[ 9];   C[15]  =  key[ 1];
   C[16]  =  key[58];   C[17]  =  key[50];
   C[18]  =  key[42];   C[19]  =  key[34];
   C[20]  =  key[26];   C[21]  =  key[18];
   C[22]  =  key[10];   C[23]  =  key[ 2];
   C[24]  =  key[59];   C[25]  =  key[51];
   C[26]  =  key[43];   C[27]  =  key[35];
   C[28]  =  key[62];   C[29]  =  key[54];
   C[30]  =  key[46];   C[31]  =  key[38];
   C[32]  =  key[30];   C[33]  =  key[22];
   C[34]  =  key[14];   C[35]  =  key[ 6];
   C[36]  =  key[61];   C[37]  =  key[53];
   C[38]  =  key[45];   C[39]  =  key[37];
   C[40]  =  key[29];   C[41]  =  key[21];
   C[42]  =  key[13];   C[43]  =  key[ 5];
   C[44]  =  key[60];   C[45]  =  key[52];
   C[46]  =  key[44];   C[47]  =  key[36];
   C[48]  =  key[28];   C[49]  =  key[20];
   C[50]  =  key[12];   C[51]  =  key[ 4];
   C[52]  =  key[27];   C[53]  =  key[19];
   C[54]  =  key[11];   C[55]  =  key[ 3];
   // End Permutation One

  /* Generate the 16 key's we will need for each round. */
  for ( int i = 0; i < ROUNDS; i++ ) {

    /*
    ** Rotate key around once for n shifts
    ** n depends on the current round we are in.
    */
    int times = SHIFTS[i];
    do{
      uint8_t c_rot = C[0];
      uint8_t d_rot = D[0];
      C[0] = C[1];  D[0] = D[1];
      C[1] = C[2];  D[1] = D[2];
      C[2] = C[3];  D[2] = D[3];
      C[3] = C[4];  D[3] = D[4];
      C[4] = C[5];  D[4] = D[5];
      C[5] = C[6];  D[5] = D[6];
      C[6] = C[7];  D[6] = D[7];
      C[7] = C[8];  D[7] = D[8];
      C[8] = C[9];  D[8] = D[9];
      C[9] = C[10];  D[9] = D[10];
      C[10] = C[11];  D[10] = D[11];
      C[11] = C[12];  D[11] = D[12];
      C[12] = C[13];  D[12] = D[13];
      C[13] = C[14];  D[13] = D[14];
      C[14] = C[15];  D[14] = D[15];
      C[15] = C[16];  D[15] = D[16];
      C[16] = C[17];  D[16] = D[17];
      C[17] = C[18];  D[17] = D[18];
      C[18] = C[19];  D[18] = D[19];
      C[19] = C[20];  D[19] = D[20];
      C[20] = C[21];  D[20] = D[21];
      C[21] = C[22];  D[21] = D[22];
      C[22] = C[23];  D[22] = D[23];
      C[23] = C[24];  D[23] = D[24];
      C[24] = C[25];  D[24] = D[25];
      C[25] = C[26];  D[25] = D[26];
      C[26] = C[27];  D[26] = D[27];
      C[27] = c_rot;  D[27] = d_rot;
    }while( --times != 0 );

    /* Copy over this rounds key (Permutation Two) */
    scheduled_keys[i][0]   =  C[13];   scheduled_keys[i][1]   =  C[16];
    scheduled_keys[i][2]   =  C[10];   scheduled_keys[i][3]   =  C[23];
    scheduled_keys[i][4]   =  C[0];    scheduled_keys[i][5]   =  C[4]; 
    scheduled_keys[i][6]   =  C[2];    scheduled_keys[i][7]   =  C[27];
    scheduled_keys[i][8]   =  C[14];   scheduled_keys[i][9]   =  C[5]; 
    scheduled_keys[i][10]  =  C[20];   scheduled_keys[i][11]  =  C[9]; 
    scheduled_keys[i][12]  =  C[22];   scheduled_keys[i][13]  =  C[18];
    scheduled_keys[i][14]  =  C[11];   scheduled_keys[i][15]  =  C[3]; 
    scheduled_keys[i][16]  =  C[25];   scheduled_keys[i][17]  =  C[7]; 
    scheduled_keys[i][18]  =  C[15];   scheduled_keys[i][19]  =  C[6]; 
    scheduled_keys[i][20]  =  C[26];   scheduled_keys[i][21]  =  C[19];
    scheduled_keys[i][22]  =  C[12];   scheduled_keys[i][23]  =  C[1]; 
    scheduled_keys[i][24]  =  C[40];   scheduled_keys[i][25]  =  C[51];
    scheduled_keys[i][26]  =  C[30];   scheduled_keys[i][27]  =  C[36];
    scheduled_keys[i][28]  =  C[46];   scheduled_keys[i][29]  =  C[54];
    scheduled_keys[i][30]  =  C[29];   scheduled_keys[i][31]  =  C[39];
    scheduled_keys[i][32]  =  C[50];   scheduled_keys[i][33]  =  C[44];
    scheduled_keys[i][34]  =  C[32];   scheduled_keys[i][35]  =  C[47];
    scheduled_keys[i][36]  =  C[43];   scheduled_keys[i][37]  =  C[48];
    scheduled_keys[i][38]  =  C[38];   scheduled_keys[i][39]  =  C[55];
    scheduled_keys[i][40]  =  C[33];   scheduled_keys[i][41]  =  C[52];
    scheduled_keys[i][42]  =  C[45];   scheduled_keys[i][43]  =  C[41];
    scheduled_keys[i][44]  =  C[49];   scheduled_keys[i][45]  =  C[35];
    scheduled_keys[i][46]  =  C[28];   scheduled_keys[i][47]  =  C[31];
    // End Permutation Two
  }
}

/*
** Get a specific bit of "data".
*/

bool DES::get( uint8_t data, const int bit ) {
  int mask = 1 << bit;
  return data & mask;
}

/*
** Turn a specific bit of "data" on.
*/

void DES::on( block_t data, const int bit ) {
  *data |= (1 << bit);
}

/*
** Turn a specific bit of "data" off.
*/

void DES::off( block_t data, const int bit ) {
  *data &= ~(1 << bit);
}

/*
** Convert a array of char to a DES block.
*/

void DES::sttoblk( block_t blk, char* str ) {
  for (int i = 0; i < 8; i++ ) {
    int j = i*8;
    blk[j+7] = DES::get(str[i],0);
    blk[j+6] = DES::get(str[i],1);
    blk[j+5] = DES::get(str[i],2);
    blk[j+4] = DES::get(str[i],3);
    blk[j+3] = DES::get(str[i],4);
    blk[j+2] = DES::get(str[i],5);
    blk[j+1] = DES::get(str[i],6);
    blk[j+0] = DES::get(str[i],7);
  }
}

/*
** Convert a DES block to array of char.
*/

void DES::blktostr( block_t blk, char* str ) {
  memset( str, 0, 8 );
  for (int i = 0; i < 8; i++ ) {

    int j = i*8;
    for (int t = 0; t < 8; t++ ) {
      if ( 1 == blk[j+t] ) {
        DES::on( (unsigned char*)&str[i], 7 - t );
      }
    }
  }
}
