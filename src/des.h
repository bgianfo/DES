/*
**
**  Authors: Sam Milton
**           Brian Gianforcaro (bjg1955@cs.rit.edu)
**
*/


#ifndef _DES_H_
#define _DES_H_


#define ROUNDS 16

class des {

  private:

    char* block;
    char* key;

    void inv_permiate( void );

    void permiate( void );

  public:

    des( char* block , char* key );

    ~des();

    void encrypt();

    void decrypt( void );
};

#endif
