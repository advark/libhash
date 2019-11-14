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
