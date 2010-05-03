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

#ifdef DESOPTIMIZED
  #include "des.hpp"
#else
  #include "des_original.hpp"
#endif

const bool DEBUG = false;

BLOCKMODE::BLOCKMODE( ) {

}

BLOCKMODE::~BLOCKMODE( void ) {

}


void BLOCKMODE::encrypt( char infile[], char outfile[], char key[] ) {

  const size_t BUFFSIZE = 8;
  char buffer[BUFFSIZE];
  char obuffer[BUFFSIZE];

  uint8_t keyblock[BKSIZE];
  uint8_t inblock[BKSIZE];

  DES::sttoblk( keyblock, key );

  // Files for reading / writing
  ifstream ifile;
  ofstream ofile;

  ifile.open( infile,  ios::binary | ios::in | ios::ate );
  ofile.open( outfile, ios::binary | ios::out );


  int size = ifile.tellg();   // Size of file
  ifile.seekg( 0, ios::beg );
  int padding = 8 - (size % 8);// Amount of padding needed
  if ( padding == 0 )
    padding = 8; // Padding cannot be 0 (pad full block)

  // Loop through all full blocks (8 bytes) of file
  for ( int i = 0; i < size / 8; i++ ) {
    ifile.read( buffer, 8 );

    DES::sttoblk( inblock, buffer );

    DES cipher( inblock, keyblock );

    cipher.encrypt();

    DES::blktostr( cipher.cipherText(), obuffer );

    if ( DEBUG ){
      for (int i = 0; i < 8; i++ ) {
        printf( "%02X ", obuffer[i] & 255 );
      }
      printf( "\n" );
    }

    ofile.write( obuffer, BUFFSIZE );
  }

  // Read remaining part of file
  if ( padding != 8 )
    ifile.read( buffer, 8 - padding );

  // Pad block with a 1 followed by 0s
  buffer[8 - padding] = 1;
  for ( int i = 1; i < padding; i++ ) {
      buffer[8 - i] = 0;
  }

  DES::sttoblk( inblock, buffer );
  DES cipher( inblock, keyblock );
  cipher.encrypt();
  uint8_t* out = cipher.cipherText();
  DES::blktostr( out, obuffer );

  if ( DEBUG ) {
    for (int i = 0; i < 8; i++ ) {
      printf("%02X ",obuffer[i] & 255 );
    }
    printf( "\n" );
  }

  ofile.write( obuffer, BUFFSIZE );
  ifile.close();
  ofile.close();
}


void BLOCKMODE::decrypt( char infile[], char outfile[], char key[] ) {

  const size_t BUFFSIZE = 8;
  char buffer[BUFFSIZE];
  char obuffer[BUFFSIZE];

  uint8_t keyblock[BKSIZE];

  DES::sttoblk( keyblock, key );

  // Files for reading / writing
  ifstream ifile;
  ofstream ofile;

  ifile.open( infile, ios::binary | ios::in | ios::ate );
  ofile.open( outfile, ofstream::binary | ios::out );


  int size = ifile.tellg(); // Size of file
  int padding = 0;           // Amount of padding on file
  uint8_t inblock[BKSIZE];   
  ifile.seekg( 0, ios::beg );

  // Loop through all but last block (8 bytes) of file
  for( int i = 0; i + 1 < size / 8; ++i ){
    ifile.read( buffer, 8 );

    DES::sttoblk( inblock, buffer );

    DES cipher( inblock, keyblock );

    cipher.decrypt();

    uint8_t* out = cipher.plainText();

    DES::blktostr( out, obuffer );

    ofile.write( obuffer, BUFFSIZE );

    if( DEBUG ){
      for (int i = 0; i < 8; i++ ) {
        printf("%02X ", obuffer[i] & 255 );
      }
      printf( "\n" );
    }
  }

  // Read last line of file
  ifile.read( buffer, 8 );

  DES::sttoblk( inblock, buffer );
  DES cipher( inblock, keyblock );
  cipher.decrypt();
  uint8_t* out = cipher.plainText();
  DES::blktostr( out, obuffer );

  // Check for and record padding on end
  for( int i = 0; obuffer[7-i] == 0; ++i ){
    ++padding;
  }
  ++padding;
  if( DEBUG ){
    for (int i = 0; i < 8; i++ ) {
      printf("%02X ", obuffer[i] & 255 );
    }
    printf( "\n" );
  }
  if( padding != 8 )
    ofile.write( obuffer, BUFFSIZE - padding );

  ifile.close();
  ofile.close();

}

