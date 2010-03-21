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

#include <algorithm>

#include "des.hpp"

/* Primative functino P pg: 22 of DES spec */
uint8_t des::P[32] = {
  16,  7, 20, 21,
  29, 12, 28, 17,
   1, 15, 23, 26,
   5, 18, 31, 10,
   2,  8, 24, 14,
  32, 27,  3,  9,
  19, 13, 30,  6,
  22, 11,  4, 25 
};

uint8_t des::E[48] = {
  32,  1,  2,  3,  4,  5, 
   4,  5,  6,  7,  8,  9, 
   8,  9, 10, 11, 12, 13, 
  12, 13, 14, 15, 16, 17, 
  16, 17, 18, 19, 20, 21, 
  20, 21, 22, 23, 24, 25, 
  24, 25, 26, 27, 28, 29, 
  28, 29, 30, 31, 32,  1
};

/* IP prime pg: 14 */
uint8_t des::IP[64] = {
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
uint8_t des::IPP[64] = {
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
uint8_t des::SP[8][64] = {

  /* S1 function pg: 19 of DES spec */
  
  {
     14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7 ,
      0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8 ,
      4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0 ,
     15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13 
  },

  /*S2 function pg: 19 of DES spec */
  { 
     15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 ,
      3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 ,
      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 ,
     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 
  },

  /*S3 function pg: 19 of DES spec */
  {
     10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 ,
     13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 ,
     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 ,
      1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 
  },

  /*S4 function pg: 19 of DES spec */
  {
      7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 ,
     13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 ,
     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 ,
      3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 
  },

  /*S5 function pg: 20 of DES spec */
  {
      2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 ,
     14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 ,
      4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 ,
     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 
  },

  /*S6 function pg: 20 of DES spec */
  {
     12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 ,
     10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 ,
      9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 ,
      4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 
  },

  /*S7 function pg: 20 of DES spec */
  {
      4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 ,
     13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 ,
      1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 ,
      6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 
  },

  /*S8 function pg: 20 of DES spec */
  {
     13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 ,
      1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 ,
      7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 ,
      2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 
  }

};


/**
 * @param block, 64 bit data block made up of two 32bit int's
 * @param key, 64 bit key made up of two 32bit int's
 */
des::des( uint8_t* block , uint8_t * key ) {

  assert( block != NULL );
  assert( key != NULL );

  this->block = new uint8_t[64];
  this->key = new uint8_t[64];

  this->key = new uint8_t[64];



  memcpy( this->block, block, 64 );
  memcpy( this->key, key, 64 );

  this->round = 0;
}

des::~des( ) {
  delete this->block;
  delete this->key;
}

/*
** Permeated choice #1 pg: 23 of DES spec
**
** Brings a 64bit key down to 56 bits.
*/

uint8_t des::PC1[56] = {
  57, 49, 41, 33, 25, 17,  9,
   1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27,
  19, 11,  3, 60, 52, 44, 36,

  63, 55, 47, 39, 31, 23, 15,
   7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29,
  21, 13,  5, 28, 20, 12,  4,
};

/*
** Permeated choice #2 pg: 23 of DES spec
** Brings a 56 bit key down to 48 bits.
*/
uint8_t des::PC2[48] = {
  14, 17, 11, 24,  1,  5,
   3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8,
  16,  7, 27, 20, 13,  2,

  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
};

/* Shift's change depending on which round we are on */
uint8_t des::SHIFTS[ROUNDS] = 
{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2 ,1 };


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


  uint8_t C[28];
  uint8_t D[28];

  /* 
   * Generate the permutation on the key 
   *
   * Discarding the lowest order bit of every byte.
   */
  for ( int i = 0; i < 28; i++ ) {
    C[i] = this->key[ PC1[ i ] - 1 ];
    D[i] = this->key[ PC1[ i + 28 ] - 1 ];
  }


  /* Generate the 16 key's we will need for each round. */
  for ( int i = 0; i < ROUNDS; i++ ) {

    /*
     * Rotate key around once for n shifts
     * n depends on the current round we are in.
     */
    for ( int j = 0; j < this->SHIFTS[i]; j++ ) {


      uint8_t tc = C[0];
      uint8_t td = D[0];
      for ( int k = 0; k < 27; k++ ) { 
        C[k] = C[k+1];
        D[k] = D[k+1];
      }
      C[27] = tc;
      D[27] = td;

    }

    /* Copy over this rounds key */ 
    for ( int j = 0; j < 24; j++ ) {
      /* Of the each 28 bit half only take 24 bits */
      this->scheduled_keys[i][j]    =  C[ PC2[j] - 1 ];
      this->scheduled_keys[i][j+24] =  D[ PC2[j+24] - 1 ];
    }
  }

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

void des::algorithm( const action_t action ) {

  this->keyschedule();

  uint8_t tmp[64]; 

  /* Perform the initial permutation on the input block */
  for ( int i = 0; i < BKSIZE; i++ ) {
    tmp[i] = this->block[ IP[i] - 1 ];
  }

  /* Split the input block */
  uint8_t* l = tmp;
  uint8_t* r = tmp + 32;

  for ( this->round = 0; this->round < ROUNDS; this->round++ ) {

    /* store r for later */
    uint8_t save[32];
    memcpy( save, r, 32 );

   
    /* Run the fiestal function */
    uint8_t fblck[32];
    des::f( fblck, r, this->scheduled_keys[this->round] );

    /* R = L ^ f(R,K) */
    for ( int j = 0; j < 32; j++ ) {
      r[j] =  l[j] ^ fblck[ P[j] -1 ];
    }

    /* Swap l and r for the next round */
    memcpy( l, save, 32 );
  }

  /* Swap output before final permutation */

  // TODO: Make sure this blatent misuse of iterators works!
  std::swap_ranges( l, l+32, r );
  

  if ( action  == encrypt_a ) {
    for ( int i = 0; i < BKSIZE; i++ ) { 
      this->ciphertext[i] = l[ IPP[i] -1 ];
    }
  } else {
    for ( int i = 0; i < BKSIZE; i++ ) { 
      this->plaintext[i] = l[ IPP[i] -1 ];
    }

  }

}

/**
 *
 * @param dest is 32 bit chunk of block
 * @param R is 48 bit chunk of block
 * @param K is 48 bit chunk of the key.
 *
 * @note input size is 2 48 bits blocks output is one 32 bit block.
 */
void des::f( uint8_t* dest, uint8_t* R, uint8_t* K ) {

  /* clear dest */
  memset( dest, 0, 32 );

  /* Expand left side to 48 bits to match key */
  uint8_t rpk[48];
  for ( int i = 0; i < 48; i++ ) {
    rpk[i] = R[ E[i] - 1 ] xor K[i];
  }


  // TODO: check to make sure this stuff is right, kind of doubting it 

  /*
   * Sbox only cares about 6 of 8 bits.
   * one iteration for every sbox 
   */
  for ( int j = 0; j < 8; j++ ) {
    uint8_t t = 6*j;

    /* Obtain the value of the sbox depending on value of previous xor */
    uint8_t in = ( rpk[t+0] << 5 ) + 
                 ( rpk[t+1] << 3 ) + 
                 ( rpk[t+2] << 2 ) + 
                 ( rpk[t+3] << 1 ) +
                 ( rpk[t+4] << 0 ) +
                 ( rpk[t+5] << 4 );

    uint8_t k = SP[j][in];

    t = 4*j;
    for (int i = 0; i < 4; i++ ) {
      dest[t+i] = (k >>(3-i)) & 01;
    }
  }
}
/**
 * Public API to encryption algorithm of the class.
 */
void des::encrypt() {
  assert( round == 0 or round >= 15 );
  this->ciphertext = new uint8_t[64];
  this->algorithm( encrypt_a );
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
  assert( round == 0 or round >= 15 );
  this->plaintext = new uint8_t[64];
  this->algorithm( decrypt_a );
}


/**
 *
 */
bool des::get( uint8_t data, const int bit ) {
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

void des::sttoblk( uint8_t* blk, char* str ) {
  for (int i = 0; i < 16; i++ ) {
    int j = i*8;
    blk[j+0] = des::get(str[i],0);
    blk[j+1] = des::get(str[i],1);
    blk[j+2] = des::get(str[i],2);
    blk[j+3] = des::get(str[i],3);
    blk[j+4] = des::get(str[i],4);
    blk[j+5] = des::get(str[i],5);
    blk[j+6] = des::get(str[i],6);
    blk[j+7] = des::get(str[i],7);
  }
}

void des::blktostr( uint8_t* blk, char* str ) {
  for (int i = 0; i < 16; i++ ) {
    int j = i*8;
    for (int t = 0; t < 8; t++ ) {
      if ( 1 == blk[j+t] ) {
        des::on( (uint8_t*)&str[i], t );
      }

    }
  }
}
