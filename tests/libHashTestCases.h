/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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

