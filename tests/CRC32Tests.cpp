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
    CRC32 crc32;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, crc32, "CRC-32", testCases[i].data, testCases[i].size, testCases[i].crc32 );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, crc32, "CRC-32", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].crc32 );
    }
}

void libHashTestCases::testCRC32BZip2( ) {
    CRC32_BZip2 crc32;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, crc32, "CRC-32-BZIP2", testCases[i].data, testCases[i].size, testCases[i].crc32bzip2 );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, crc32, "CRC-32-BZIP2", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].crc32bzip2 );
    }
}

void libHashTestCases::testCRC32C( ) {
    CRC32C crc32;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, crc32, "CRC-32C", testCases[i].data, testCases[i].size, testCases[i].crc32c );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, crc32, "CRC-32", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].crc32c );
    }
}
