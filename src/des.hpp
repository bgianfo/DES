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

class des {

  private:

    static uint8_t des::SHIFTS[ROUNDS];

    /* Primative functino P pg: 22 of DES spec */
    static uint8_t des::P[32];

    static uint8_t des::E[48];

    /* Permiated choice #1 pg: 23 of DES spec */
    static uint8_t des::PC1[56];

    static uint8_t des::PC2[56];

    /* IP prime pg: 14 */
    static uint8_t des::IP[64];

    /* IP prime pg: 14 */
    static uint8_t des::IPP[64];

    /* All S-Boxes  */
    static uint8_t des::SP[8][4][16];

    uint8_t* block;

    uint8_t* key;

    uint8_t round;

    void inv_permiate( void );

    void permiate( void );

    void f( char* L, char* K );

    void keyschedule( void );

    static bool get( uint8_t data, int bit );

    static void on( uint8_t* data, const int bit );

    static void off( uint8_t* data, const int bit );
 

  public:

    des( uint8_t* block , uint8_t* key );

    ~des();

    void encrypt();

    void decrypt( void );
};

#endif
