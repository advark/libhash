/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
