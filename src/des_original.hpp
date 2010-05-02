/*
**  File: des.hpp
*
**  Authors: 
** 
**     Sam Milton        (srm2997@cs.rit.edu)
**     Brian Gianforcaro (bjg1955@cs.rit.edu)
**
*/

#ifndef _DES_HPP_
#define _DES_HPP_

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
    uint8_t scheduled_keys[ROUNDS][48];

    /* Encrypted cipher text */
    uint8_t* ciphertext;

    /* Decrypted plain text */
    uint8_t* plaintext;

    void mixer( uint8_t block[], uint8_t out[], uint8_t mix[], int size );

    /* DES Fiestal function */
    void f( block_t dest, block_t R, block_t K );

    /* Schedule keys for all rounds */
    void keyschedule( void );

    /* Main entry point to DES cipher */
    void algorithm( action_t action );

  public:

    /* Constructor */
    DES( uint8_t* block , uint8_t* key );

    /* Destructor */
    ~DES( void );

    void encrypt( void );

    void decrypt( void );

    uint8_t* cipherText( void ) {
      return this->ciphertext;
    }

    uint8_t* plainText( void ) {
      return this->plaintext;
    }

    static void sttoblk( block_t blk, char* str );

    static void blktostr( block_t blk, char* str );

    /* Get the nth bit of a integer */
    static bool get( uint8_t data, const int bit );

    /* Set the nth bit of a integer */
    static void on( uint8_t* data, const int bit );

    /* Un-set the nth bit of a integer */
    static void off( uint8_t* data, const int bit );

};

#endif
