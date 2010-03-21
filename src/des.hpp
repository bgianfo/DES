/*
**
**  Authors: Sam Milton
**           Brian Gianforcaro (bjg1955@cs.rit.edu)
**
*/


#ifndef _DES_H_
#define _DES_H_

#include <stdint.h>

#ifdef UNITTEST
 #define protected public
 #define private   public
#endif

#define ROUNDS 16
#define BKSIZE 64

enum action_t {
  encrypt_a, 
  decrypt_a
};

class des {

  private:

    //
    // Constants as defined in the spec
    //

    /* Number of shifts for each round */
    static uint8_t des::SHIFTS[ROUNDS];

    /* Primitive function P pg: 22 of DES spec */
    static uint8_t des::P[32];

    static uint8_t des::E[48];

    /* Permeated choice #1 pg: 23 of DES spec */
    static uint8_t des::PC1[56];

    static uint8_t des::PC2[48];

    /* IP prime pg: 14 */
    static uint8_t des::IP[64];

    /* IP prime pg: 14 */
    static uint8_t des::IPP[64];

    /* All S-Boxes  */
    static uint8_t des::SP[8][64];

    //
    // Class state
    //

    uint8_t* block;

    uint8_t* key;

    uint8_t round;

    uint8_t scheduled_keys[16][48];

    uint8_t* ciphertext;
    uint8_t* plaintext;

    void f( uint8_t* dest, uint8_t* R, uint8_t* K );

    void keyschedule( void );

    static bool get( uint8_t data, const int bit );

    static void on( uint8_t* data, const int bit );

    static void off( uint8_t* data, const int bit );
 
    void algorithm( action_t action );

  public:

    des( uint8_t* block , uint8_t* key );

    ~des();

    void encrypt( void );

    void decrypt( void );

    uint8_t* cipherText(void) { return this->ciphertext; }
    uint8_t* plainText(void) { return this->plaintext; }

    static void sttoblk( uint8_t* blk, char* str );

    static void blktostr( uint8_t* blk, char* str );
};

#endif
