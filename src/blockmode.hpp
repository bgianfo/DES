/*
**  File: blockmode.hpp
**
**  Authors: 
** 
**     Sam Milton        (srm2997@cs.rit.edu)
**     Brian Gianforcaro (bjg1955@cs.rit.edu)
**
*/

enum mode_t {
  CBC, ECB
};


class BLOCKMODE {

  private:

  public:

    BLOCKMODE( mode_t mode );

    ~BLOCKMODE( void );

    char* encrypt( char file[], char key[] );

}
