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

void libHashTestCases::testMD5( ) {
    char *msg;
    MD5 md5;

    uint8_t result[md5.getHashSize( ) / 8];

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        md5.init( );
        md5.update( testCases[i].data, testCases[i].size );
        md5.finalize( );
        md5.getValue( result, sizeof ( result ) );

        if( memcmp( result, testCases[i].md5, sizeof ( result ) ) != 0 ) {
            asprintf( &msg,
                      "MD5 Test #%d failed.\n"
                      "     Result  = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "     Expected= %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      i + 1,
                      result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
                      result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15],
                      testCases[i].md5[0], testCases[i].md5[1], testCases[i].md5[2], testCases[i].md5[3],
                      testCases[i].md5[4], testCases[i].md5[5], testCases[i].md5[6], testCases[i].md5[7],
                      testCases[i].md5[8], testCases[i].md5[9], testCases[i].md5[10], testCases[i].md5[11],
                      testCases[i].md5[12], testCases[i].md5[13], testCases[i].md5[14], testCases[i].md5[15] );

            CPPUNIT_FAIL( msg );
            free( msg );
        }
    }
}

