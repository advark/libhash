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
    SHA2_224 sha2;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, sha2, "SHA-2 224-bits", testCases[i].data, testCases[i].size, testCases[i].sha2_224 );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, sha2, "SHA-2 224-bits", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].sha2_224 );
    }
}

void libHashTestCases::testSHA2_256( ) {
    SHA2_256 sha2;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, sha2, "SHA-2 256-bits", testCases[i].data, testCases[i].size, testCases[i].sha2_256 );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, sha2, "SHA-2 256-bits", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].sha2_256 );
    }
}

void libHashTestCases::testSHA2_384( ) {
    SHA2_384 sha2;

    for( int i = 1; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, sha2, "SHA-2 384-bits", testCases[i].data, testCases[i].size, testCases[i].sha2_384 );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, sha2, "SHA-2 384-bits", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].sha2_384 );
    }
}

void libHashTestCases::testSHA2_512( ) {
    SHA2_512 sha2;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, sha2, "SHA-2 512-bits", testCases[i].data, testCases[i].size, testCases[i].sha2_512 );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, sha2, "SHA-2 512-bits", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].sha2_512 );
    }
}

