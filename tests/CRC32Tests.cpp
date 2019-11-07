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

void libHashTestCases::testCRC32( ) {
    char *msg;
    CRC32 crc32;

    uint8_t result[crc32.getHashSize( ) / 8];

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        crc32.init( );
        crc32.update( testCases[i].data, testCases[i].size );
        crc32.finalize( );
        crc32.getValue( result, sizeof ( result ) );

        if( memcmp( result, testCases[i].crc32, sizeof ( result ) ) != 0 ) {
            asprintf( &msg,
                      "CRC32 Test #%d failed.\n"
                      "     Result  = %02x%02x%02x%02x\n"
                      "     Expected= %02x%02x%02x%02x",
                      i + 1,
                      result[0], result[1], result[2], result[3],
                      testCases[i].crc32[0], testCases[i].crc32[1], testCases[i].crc32[2], testCases[i].crc32[3] );

            CPPUNIT_FAIL( msg );
            free( msg );
        }
    }
}

void libHashTestCases::testCRC32C( ) {
    char *msg;
    CRC32C crc32c;

    uint8_t result[crc32c.getHashSize( ) / 8];

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        crc32c.init( );
        crc32c.update( testCases[i].data, testCases[i].size );
        crc32c.finalize( );
        crc32c.getValue( result, sizeof ( result ) );

        if( memcmp( result, testCases[i].crc32c, sizeof ( result ) ) != 0 ) {
            asprintf( &msg,
                      "CRC32C Test #%d failed.\n"
                      "     Result  = %02x%02x%02x%02x\n"
                      "     Expected= %02x%02x%02x%02x",
                      i + 1,
                      result[0], result[1], result[2], result[3],
                      testCases[i].crc32c[0], testCases[i].crc32c[1], testCases[i].crc32c[2], testCases[i].crc32c[3] );

            CPPUNIT_FAIL( msg );
            free( msg );
        }
    }
}
