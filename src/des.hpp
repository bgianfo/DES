/*
**  File: des.hpp
**
**  Authors: 
** 
**     Sam Milton        (srm2997@cs.rit.edu)
**     Brian Gianforcaro (bjg1955@cs.rit.edu)
**
*/

#ifndef _DES_H_
#define _DES_H_

#include <stdint.h>

/* Convenience for unit testing */
#ifdef UNITTEST
# define protected public
# define private   public
#endif

/* Number of rounds in cipher*/
#define ROUNDS 16

/* Initial size of block and key in bits*/
#define BKSIZE 64

/* Define which action's for the algorithm */
enum action_t {
  encrypt_a, decrypt_a
};


/* Define a block type to use */
typedef uint8_t* block_t;

class DES {

  private:

    /*
    ** Constants as defined in the spec
    */

    /* Number of shifts for each round */
    static uint8_t SHIFTS[ROUNDS];

    /* Primitive function P pg: 22 of DES spec */
    static uint8_t P[(BKSIZE/2)];

    /* Primitive function E */
    static uint8_t E[48];

    /* Permeated choice #1 pg: 23 of DES spec */
    static uint8_t PC1[56];

    /* Permeated choice #2 pg: 23 of DES spec */
    static uint8_t PC2[48];

    /* Initial permutation pg: 14 */
    static uint8_t IP[BKSIZE];

    /* Final permutation, or IP prime pg: 14 */
    static uint8_t IPP[BKSIZE];

    /* All S-Boxes 1-8 */
    static uint8_t SP[8][4][16];

    /*
    ** Class state
    */

    /* Data block 64 long */
    uint8_t* block;

    /* Data key block 64 long */
    uint8_t* key;

    /* Data key current round of cipher */
    uint8_t round;

    /* All scheduled key's */
    uint8_t scheduled_keys[16][48];

    /* Encrypted cipher text */
    block_t ciphertext;

    /* Decrypted plain text */
    block_t plaintext;

    /* DES Fiestal function */
    void f( block_t dest, block_t R, block_t K );

    /* Schedule keys for all rounds */
    void keyschedule( void );

    /* Main entry point to DES cipher */
    void algorithm( action_t action );

    void primative( uint8_t block[], uint8_t out[] );

    void initPermutation( uint8_t block[], uint8_t out[] );

    void inverseInitPermutation( uint8_t block[], uint8_t out[] );

    void permutation_one( uint8_t key[], uint8_t out[] );

    void permutation_two( uint8_t key[], uint8_t out[] );

    void expand( block_t key, uint8_t out[] );

  public:

    /* Constructor */
    DES( block_t block , block_t key );

    /* Destructor */
    ~DES( void );

    void encrypt( void );

    void decrypt( void );

    uint8_t* cipherText( void ) { return this->ciphertext; }

    uint8_t* plainText( void ) { return this->plaintext; }

    static void sttoblk( block_t blk, char* str );

    static void blktostr( block_t blk, char* str );

    /* Get the nth bit of a integer */
    static bool get( uint8_t data, const int bit );

    /* Set the nth bit of a integer */
    static void on( block_t data, const int bit );

    /* Un-set the nth bit of a integer */
    static void off( block_t data, const int bit );

};

#endif
