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
 * File:   CRC16_Test.cpp
 * Author: Yanick Poirier <ypoirier at hotmail.com>
 *
 * Created on 2019-11-09, 21:05:16
 */

#include <libhash/libhash.h>
#include <string.h>
#include "libHashTestCases.h"

using namespace libhash;

void libHashTestCases::testCRC16_CCITT( ) {
    CRC16_CCITT crc16;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, crc16, "CRC-16-CCITT", testCases[i].data, testCases[i].size, testCases[i].crc16ccitt );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, crc16, "CRC-16-CCITT", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].crc16ccitt );
    }
}

void libHashTestCases::testCRC16_XModem( ) {
    CRC16_XModem crc16;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, crc16, "CRC-16-XModem", testCases[i].data, testCases[i].size, testCases[i].crc16xmodem );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, crc16, "CRC-16-XModem", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].crc16xmodem );
    }
}

void libHashTestCases::testCRC16_X25( ) {
    CRC16_X25 crc16;

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runSingleChunk( i + 1, crc16, "CRC-16-X25", testCases[i].data, testCases[i].size, testCases[i].crc16x25 );
    }

    for( int i = 0; i < sizeof ( testCases ) / sizeof ( TestData ); i++ ) {
        runMultiChunk( 11 + i, crc16, "CRC-16-X25", testCases[i].data, testCases[i].size, ( testCases[i].size * 0.13 ) + 1, testCases[i].crc16x25 );
    }
}
