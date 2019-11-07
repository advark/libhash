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

#    include <cppunit/extensions/HelperMacros.h>

struct TestData {
    char *data;
    uint32_t size;
    uint8_t crc32[4];
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

    CPPUNIT_TEST( testCRC32 );
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
    void testCRC32( );
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

