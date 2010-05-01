/*
**  File: blockmode.hpp
**
**  Authors:
**
**     Sam Milton        (srm2997@cs.rit.edu)
**     Brian Gianforcaro (bjg1955@cs.rit.edu)
**
*/

#ifndef _BLOCKMODE_HPP_
#define _BLOCKMODE_HPP_


class BLOCKMODE {

  public:

    BLOCKMODE( );

    ~BLOCKMODE( void );

    void encrypt( char file[], char ofile[], char key[] );

    void decrypt( char file[], char ofile[], char key[] );

};

#endif
