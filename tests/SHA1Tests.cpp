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

void libHashTestCases::testSHA1( ) {
    char *msg;
    SHA1 sha1;

    uint8_t result[sha1.getHashSize( ) / 8];

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        sha1.init( );
        sha1.update( testCases[i].data, testCases[i].size );
        sha1.finalize( );
        sha1.getValue( result, sizeof ( result ) );

        if( memcmp( result, testCases[i].sha1, sizeof ( result ) ) != 0 ) {
            asprintf( &msg,
                      "SHA1 Test #%d failed.\n"
                      "     Result  = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
                      "     Expected= %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      i + 1,
                      result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
                      result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15],
                      result[16], result[17], result[18], result[19],
                      testCases[i].sha1[0], testCases[i].sha1[1], testCases[i].sha1[2], testCases[i].sha1[3],
                      testCases[i].sha1[4], testCases[i].sha1[5], testCases[i].sha1[6], testCases[i].sha1[7],
                      testCases[i].sha1[8], testCases[i].sha1[9], testCases[i].sha1[10], testCases[i].sha1[11],
                      testCases[i].sha1[12], testCases[i].sha1[13], testCases[i].sha1[14], testCases[i].sha1[15],
                      testCases[i].sha1[16], testCases[i].sha1[17], testCases[i].sha1[18], testCases[i].sha1[19] );

            CPPUNIT_FAIL( msg );
            free( msg );
        }
    }
}

