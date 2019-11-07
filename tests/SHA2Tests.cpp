/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   CRC32_Test.cpp
 * Author: Yanick Poirier <ypoirier at hotmail.com>
 *
 * Created on 2019-11-01, 21:05:16
 */

#include <libhash/libhash.h>
#include <string.h>
#include "libHashTestCases.h"

using namespace libhash;

void libHashTestCases::testSHA2_224( ) {
    char *msg;
    SHA2_224 sha2;

    uint8_t result[sha2.getHashSize( ) / 8];

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        sha2.init( );
        sha2.update( testCases[i].data, testCases[i].size );
        sha2.finalize( );
        sha2.getValue( result, sizeof ( result ) );

        if( memcmp( result, testCases[i].sha2_224, sizeof ( result ) ) != 0 ) {
            asprintf( &msg,
                      "SHA2-224 Test #%d failed.\n"
                      "     Result  = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "     Expected= %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      i + 1,
                      result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
                      result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15],
                      result[16], result[17], result[18], result[19], result[20], result[21], result[22], result[23],
                      result[24], result[25], result[26], result[27],
                      testCases[i].sha2_224[0], testCases[i].sha2_224[1], testCases[i].sha2_224[2], testCases[i].sha2_224[3],
                      testCases[i].sha2_224[4], testCases[i].sha2_224[5], testCases[i].sha2_224[6], testCases[i].sha2_224[7],
                      testCases[i].sha2_224[8], testCases[i].sha2_224[9], testCases[i].sha2_224[10], testCases[i].sha2_224[11],
                      testCases[i].sha2_224[12], testCases[i].sha2_224[13], testCases[i].sha2_224[14], testCases[i].sha2_224[15],
                      testCases[i].sha2_224[16], testCases[i].sha2_224[17], testCases[i].sha2_224[18], testCases[i].sha2_224[19],
                      testCases[i].sha2_224[20], testCases[i].sha2_224[21], testCases[i].sha2_224[22], testCases[i].sha2_224[23],
                      testCases[i].sha2_224[24], testCases[i].sha2_224[25], testCases[i].sha2_224[26], testCases[i].sha2_224[27] );

            CPPUNIT_FAIL( msg );
            free( msg );
        }
    }
}

void libHashTestCases::testSHA2_256( ) {
    char *msg;
    SHA2_256 sha2;

    uint8_t result[sha2.getHashSize( ) / 8];

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        sha2.init( );
        sha2.update( testCases[i].data, testCases[i].size );
        sha2.finalize( );
        sha2.getValue( result, sizeof ( result ) );

        if( memcmp( result, testCases[i].sha2_256, sizeof ( result ) ) != 0 ) {
            asprintf( &msg,
                      "SHA2-256 Test #%d failed.\n"
                      "     Result  = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "     Expected= %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      i + 1,
                      result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
                      result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15],
                      result[16], result[17], result[18], result[19], result[20], result[21], result[22], result[23],
                      result[24], result[25], result[26], result[27], result[28], result[29], result[30], result[31],
                      testCases[i].sha2_256[0], testCases[i].sha2_256[1], testCases[i].sha2_256[2], testCases[i].sha2_256[3],
                      testCases[i].sha2_256[4], testCases[i].sha2_256[5], testCases[i].sha2_256[6], testCases[i].sha2_256[7],
                      testCases[i].sha2_256[8], testCases[i].sha2_256[9], testCases[i].sha2_256[10], testCases[i].sha2_256[11],
                      testCases[i].sha2_256[12], testCases[i].sha2_256[13], testCases[i].sha2_256[14], testCases[i].sha2_256[15],
                      testCases[i].sha2_256[16], testCases[i].sha2_256[17], testCases[i].sha2_256[18], testCases[i].sha2_256[19],
                      testCases[i].sha2_256[20], testCases[i].sha2_256[21], testCases[i].sha2_256[22], testCases[i].sha2_256[23],
                      testCases[i].sha2_256[24], testCases[i].sha2_256[25], testCases[i].sha2_256[26], testCases[i].sha2_256[27],
                      testCases[i].sha2_256[28], testCases[i].sha2_256[29], testCases[i].sha2_256[30], testCases[i].sha2_256[31] );

            CPPUNIT_FAIL( msg );
            free( msg );
        }
    }
}

void libHashTestCases::testSHA2_384( ) {
    char *msg;
    SHA2_384 sha2;

    uint8_t result[sha2.getHashSize( ) / 8];

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        sha2.init( );
        sha2.update( testCases[i].data, testCases[i].size );
        sha2.finalize( );
        sha2.getValue( result, sizeof ( result ) );

        if( memcmp( result, testCases[i].sha2_384, sizeof ( result ) ) != 0 ) {
            asprintf( &msg,
                      "SHA2-384 Test #%d failed.\n"
                      "     Result  = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "     Expected= %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      i + 1,
                      result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
                      result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15],
                      result[16], result[17], result[18], result[19], result[20], result[21], result[22], result[23],
                      result[24], result[25], result[26], result[27], result[28], result[29], result[30], result[31],
                      result[32], result[33], result[34], result[35], result[36], result[37], result[38], result[39],
                      result[40], result[41], result[42], result[43], result[44], result[45], result[46], result[47],
                      testCases[i].sha2_384[0], testCases[i].sha2_384[1], testCases[i].sha2_384[2], testCases[i].sha2_384[3],
                      testCases[i].sha2_384[4], testCases[i].sha2_384[5], testCases[i].sha2_384[6], testCases[i].sha2_384[7],
                      testCases[i].sha2_384[8], testCases[i].sha2_384[9], testCases[i].sha2_384[10], testCases[i].sha2_384[11],
                      testCases[i].sha2_384[12], testCases[i].sha2_384[13], testCases[i].sha2_384[14], testCases[i].sha2_384[15],
                      testCases[i].sha2_384[16], testCases[i].sha2_384[17], testCases[i].sha2_384[18], testCases[i].sha2_384[19],
                      testCases[i].sha2_384[20], testCases[i].sha2_384[21], testCases[i].sha2_384[22], testCases[i].sha2_384[23],
                      testCases[i].sha2_384[24], testCases[i].sha2_384[25], testCases[i].sha2_384[26], testCases[i].sha2_384[27],
                      testCases[i].sha2_384[28], testCases[i].sha2_384[29], testCases[i].sha2_384[30], testCases[i].sha2_384[31],
                      testCases[i].sha2_384[32], testCases[i].sha2_384[33], testCases[i].sha2_384[34], testCases[i].sha2_384[35],
                      testCases[i].sha2_384[36], testCases[i].sha2_384[37], testCases[i].sha2_384[38], testCases[i].sha2_384[39],
                      testCases[i].sha2_384[40], testCases[i].sha2_384[41], testCases[i].sha2_384[42], testCases[i].sha2_384[43],
                      testCases[i].sha2_384[44], testCases[i].sha2_384[45], testCases[i].sha2_384[46], testCases[i].sha2_384[47] );

            CPPUNIT_FAIL( msg );
            free( msg );
        }
    }
}

void libHashTestCases::testSHA2_512( ) {
    char *msg;
    SHA2_512 sha2;

    uint8_t result[sha2.getHashSize( ) / 8];

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        sha2.init( );
        sha2.update( testCases[i].data, testCases[i].size );
        sha2.finalize( );
        sha2.getValue( result, sizeof ( result ) );

        if( memcmp( result, testCases[i].sha2_512, sizeof ( result ) ) != 0 ) {
            asprintf( &msg,
                      "SHA2-512 Test #%d failed.\n"
                      "     Result  = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "     Expected= %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "               %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      i + 1,
                      result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
                      result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15],
                      result[16], result[17], result[18], result[19], result[20], result[21], result[22], result[23],
                      result[24], result[25], result[26], result[27], result[28], result[29], result[30], result[31],
                      result[32], result[33], result[34], result[35], result[36], result[37], result[38], result[39],
                      result[40], result[41], result[42], result[43], result[44], result[45], result[46], result[47],
                      result[48], result[49], result[50], result[51], result[52], result[53], result[54], result[55],
                      result[56], result[57], result[58], result[59], result[60], result[61], result[62], result[63],
                      testCases[i].sha2_512[0], testCases[i].sha2_512[1], testCases[i].sha2_512[2], testCases[i].sha2_512[3],
                      testCases[i].sha2_512[4], testCases[i].sha2_512[5], testCases[i].sha2_512[6], testCases[i].sha2_512[7],
                      testCases[i].sha2_512[8], testCases[i].sha2_512[9], testCases[i].sha2_512[10], testCases[i].sha2_512[11],
                      testCases[i].sha2_512[12], testCases[i].sha2_512[13], testCases[i].sha2_512[14], testCases[i].sha2_512[15],
                      testCases[i].sha2_512[16], testCases[i].sha2_512[17], testCases[i].sha2_512[18], testCases[i].sha2_512[19],
                      testCases[i].sha2_512[20], testCases[i].sha2_512[21], testCases[i].sha2_512[22], testCases[i].sha2_512[23],
                      testCases[i].sha2_512[24], testCases[i].sha2_512[25], testCases[i].sha2_512[26], testCases[i].sha2_512[27],
                      testCases[i].sha2_512[28], testCases[i].sha2_512[29], testCases[i].sha2_512[30], testCases[i].sha2_512[31],
                      testCases[i].sha2_512[32], testCases[i].sha2_512[33], testCases[i].sha2_512[34], testCases[i].sha2_512[35],
                      testCases[i].sha2_512[36], testCases[i].sha2_512[37], testCases[i].sha2_512[38], testCases[i].sha2_512[39],
                      testCases[i].sha2_512[40], testCases[i].sha2_512[41], testCases[i].sha2_512[42], testCases[i].sha2_512[43],
                      testCases[i].sha2_512[44], testCases[i].sha2_512[45], testCases[i].sha2_512[46], testCases[i].sha2_512[47],
                      testCases[i].sha2_512[48], testCases[i].sha2_512[49], testCases[i].sha2_512[50], testCases[i].sha2_512[51],
                      testCases[i].sha2_512[52], testCases[i].sha2_512[53], testCases[i].sha2_512[54], testCases[i].sha2_512[55],
                      testCases[i].sha2_512[56], testCases[i].sha2_512[57], testCases[i].sha2_512[58], testCases[i].sha2_512[59],
                      testCases[i].sha2_512[60], testCases[i].sha2_512[61], testCases[i].sha2_512[62], testCases[i].sha2_512[63] );

            CPPUNIT_FAIL( msg );
            free( msg );
        }
    }
}

