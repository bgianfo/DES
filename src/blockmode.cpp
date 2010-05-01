/*
**  File: blockmode.cpp
**
**  Authors:
**
**     Sam Milton        (srm2997@cs.rit.edu)
**     Brian Gianforcaro (bjg1955@cs.rit.edu)
**
**  Description:
**
**  Implementation of all the block modes for DES.
*/

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <stdint.h>
#include <iostream>
#include <fstream>

using namespace std;

#include "blockmode.hpp"
#include "des.hpp"

BLOCKMODE::BLOCKMODE( ) {

}

BLOCKMODE::~BLOCKMODE( void ) {

}


void BLOCKMODE::encrypt( char file[], char outfile[], char key[] ) {

  const size_t BUFFSIZE = 8;
  char buffer[BUFFSIZE];
  char obuffer[BUFFSIZE];

  uint8_t keyblock[BKSIZE];
  uint8_t inblock[BKSIZE];

  DES::sttoblk( keyblock, key );


  ifstream infile;
  infile.open( file, ios::binary );

  ofstream ofile;
  ofile.open( outfile, ofstream::binary );


  int padding;
  while( (padding = 8 - infile.readsome( buffer, BUFFSIZE ) ) == 0 ){

    printf("\n");
    memset( inblock, 0, 8 );
    DES::sttoblk( inblock, buffer );

    DES cipher( inblock, keyblock );

    cipher.encrypt();

    uint8_t* out = cipher.cipherText();

    memset( obuffer, 0, 8 );
    DES::blktostr( out, obuffer );

    for (int i = 0; i < 8; i++ ) {
      printf("%d ", obuffer[i]);
    }
    ofile.write( obuffer, BUFFSIZE );
  }

  printf("\n");

  for (int i = 0; i < padding; i++ ) {
    if ( i+1 == padding ) {
      buffer[7-i] = 1;
    } else {
      buffer[7-i] = 0;
    }
  }

  DES::sttoblk( inblock, buffer );
  DES cipher( inblock, keyblock );
  cipher.encrypt();
  uint8_t* out = cipher.cipherText();
  DES::blktostr( out, obuffer );
  for (int i = 0; i < 8; i++ ) {
    printf("%c",obuffer[i]);

  }
  ofile.write( obuffer, BUFFSIZE );

  infile.close();
  ofile.close();

}


void BLOCKMODE::decrypt( char file[], char outfile[], char key[] ) {

  const size_t BUFFSIZE = 8;
  char buffer[BUFFSIZE];
  char obuffer[BUFFSIZE];

  uint8_t keyblock[BKSIZE];

  DES::sttoblk( keyblock, key );


  ifstream infile;
  infile.open( file, ios::binary );

  ofstream ofile;
  ofile.open( outfile, ofstream::binary );


  int padding;
  uint8_t inblock[BKSIZE];
  printf("Got to while");
  while( (padding = 8 - infile.readsome( buffer, BUFFSIZE ) ) == 0 ){
    printf("\n");

    DES::sttoblk( inblock, buffer );

    DES cipher( inblock, keyblock );

    cipher.decrypt();

    uint8_t* out = cipher.plainText();

    DES::blktostr( out, obuffer );

    for (int i = 0; i < 8; i++ ) {
      printf("%c",obuffer[i]);

    }
    ofile.write( obuffer, BUFFSIZE );

  }

  printf("\n");

  for (int i = 0; i < padding; i++ ) {
    if ( i+1 == padding ) {
      buffer[7-i] = 1;
    } else {
      buffer[7-i] = 0;
    }
  }
  DES::sttoblk( inblock, buffer );
  DES cipher( inblock, keyblock );
  cipher.encrypt();
  uint8_t* out = cipher.cipherText();
  DES::blktostr( out, obuffer );
  for (int i = 0; i < 8; i++ ) {
    printf("%c",obuffer[i]);

  }
  ofile.write( obuffer, BUFFSIZE );

  infile.close();
  ofile.close();

}

