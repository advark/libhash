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
 * File:   CRC32_Test.h
 * Author: Yanick Poirier <ypoirier at hotmail.com>
 *
 * Created on 2019-11-01, 21:05:15
 */

#ifndef LIBHASH_TESTCASE_H
#    define LIBHASH_TESTCASE_H

#    include <libhash/libhash.h>
#    include <cppunit/extensions/HelperMacros.h>

using namespace libhash;

struct TestData {
    char *data;
    uint32_t size;
    uint8_t crc16ccitt[2];
    uint8_t crc16xmodem[2];
    uint8_t crc16x25[2];
    uint8_t crc32[4];
    uint8_t crc32bzip2[4];
    uint8_t crc32c[4];
    uint8_t md5[16];
    uint8_t sha1[20];
    uint8_t sha2_224[28];
    uint8_t sha2_256[32];
    uint8_t sha2_384[48];
    uint8_t sha2_512[64];
} ;

class libHashTestCases : public CPPUNIT_NS::TestFixture {
    CPPUNIT_TEST_SUITE( libHashTestCases );

    CPPUNIT_TEST( testCRC16_CCITT );
    CPPUNIT_TEST( testCRC16_XModem );
    CPPUNIT_TEST( testCRC16_X25 );
    CPPUNIT_TEST( testCRC32 );
    CPPUNIT_TEST( testCRC32BZip2 );
    CPPUNIT_TEST( testCRC32C );
    CPPUNIT_TEST( testMD5 );
    CPPUNIT_TEST( testSHA1 );
    CPPUNIT_TEST( testSHA2_224 );
    CPPUNIT_TEST( testSHA2_256 );
    CPPUNIT_TEST( testSHA2_384 );
    CPPUNIT_TEST( testSHA2_512 );

    CPPUNIT_TEST_SUITE_END( );

public:
    libHashTestCases( );
    virtual ~libHashTestCases( );
    void setUp( );
    void tearDown( );

private:
    void runSingleChunk( int testNo, HashingBase &pHash, const char *name, void *data, uint32_t size, uint8_t expected[] );
    void runMultiChunk( int testNo, HashingBase &pHash, const char *name, void *data, uint32_t size, uint32_t chunkSize, uint8_t expected[] );
    void testCRC16_CCITT( );
    void testCRC16_XModem( );
    void testCRC16_X25( );
    void testCRC32( );
    void testCRC32BZip2( );
    void testCRC32C( );
    void testMD5( );
    void testSHA1( );
    void testSHA2_224( );
    void testSHA2_256( );
    void testSHA2_384( );
    void testSHA2_512( );

    static TestData testCases[10];
} ;

#endif /* LIBHASH_TESTCASE_H */

