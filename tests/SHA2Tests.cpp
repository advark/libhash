/*
 * Copyright (C) 2017-19 Yanick Poirier <ypoirier at hotmail.com>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
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

