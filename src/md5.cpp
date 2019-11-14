/*
 * Copyright (C) 2017-19 Yanick Poirier <ypoirier at hotmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//=============================================================================
// System:     libHash
// File:       md5.cpp
//
// Author:     Yanick Poirier
// Date:       2017-01-21
//
// Description
// MD5 hashing algorithm implementation
//
// Derived from the RSA Data Security, Inc.
// MD5 Message-Digest Algorithm
//=============================================================================

// ============================================================================
// HEADER FILES
// ============================================================================

#include <stdlib.h>
#include <string.h>
#include "../include/libhash/defs.h"
#include "../include/libhash/hashbase.h"
#include "../include/libhash/md5.h"

using namespace libhash;

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

// Constants for transform routine. */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

// ============================================================================
// STRUCTURES & TYPEDEFS
// ============================================================================

// ============================================================================
// CLASSES
// ============================================================================

// ============================================================================
// PROTOTYPES
// ============================================================================

// F, G, H and I are basic MD5 functions.

inline uint32_t F( uint32_t x, uint32_t y, uint32_t z ) {
    return ( x & y ) | ( ~x & z );
}

inline uint32_t G( uint32_t x, uint32_t y, uint32_t z ) {
    return ( x & z ) | ( y & ~z );
}

inline uint32_t H( uint32_t x, uint32_t y, uint32_t z ) {
    return x ^ y ^ z;
}

inline uint32_t I( uint32_t x, uint32_t y, uint32_t z ) {
    return y ^ ( x | ~z );
}

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.

inline void FF( uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac ) {
    a += F( b, c, d ) + x + ac;
    a = ROTL( a, s, 32 );
    a += b;
}

inline void GG( uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac ) {
    a += G( b, c, d ) + x + ac;
    a = ROTL( a, s, 32 );
    a += b;
}

inline void HH( uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac ) {
    a += H( b, c, d ) + x + ac;
    a = ROTL( a, s, 32 );
    a += b;
}

inline void II( uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac ) {
    a += I( b, c, d ) + x + ac;
    a = ROTL( a, s, 32 );
    a += b;
}

/**
 * @internal
 *
 * Encodes input (uint32_t) into output (uint8_t). Assumes len is a multiple of
 * 4. Values are encoded in little-endian format.
 */
static void encode( uint8_t *output, uint32_t *input, uint32_t len ) {
    unsigned int i, j;

    for( i = 0, j = 0; j < len; i++, j += 4 ) {
        output[ j ] = (uint8_t) ( input[ i ] & 0xff );
        output[ j + 1 ] = (uint8_t) ( ( input[ i ] & 0x0000ff00 ) >> 8 );
        output[ j + 2 ] = (uint8_t) ( ( input[ i ] & 0x00ff0000 ) >> 16 );
        output[ j + 3 ] = (uint8_t) ( ( input[ i ] & 0xff000000 ) >> 24 );
    }
}

/**
 * @internal
 *
 * Decodes input (uint8_t) into output (uint32_t). Assumes len is a multiple of
 * 4. Values are decoded from little-endian format.
 */
static void decode( uint32_t *output, uint8_t *input, uint32_t len ) {
    uint32_t i, j;

    for( i = 0, j = 0; j < len; i++, j += 4 ) {
        output[ i ] = ( (uint32_t) input[ j ] ) |
                ( ( (uint32_t) input[ j + 1 ] ) << 8 ) |
                ( ( (uint32_t) input[ j + 2 ] ) << 16 ) |
                ( ( (uint32_t) input[ j + 3 ] ) << 24 );
    }
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

// -------------------------------------------------------------------------
static unsigned char PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * @copydoc HashingBase::init()
 */
void MD5::init( ) {
    mBitCount[ 0 ] = 0;
    mBitCount[ 1 ] = 0;

    // Load magic initialization constants.
    mState[ 0 ] = 0x67452301;
    mState[ 1 ] = 0xefcdab89;
    mState[ 2 ] = 0x98badcfe;
    mState[ 3 ] = 0x10325476;
}

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void MD5::update( const void *data, size_t size ) {
    uint32_t i, index, partLen;

    // Compute number of bytes mod 64
    index = ( mBitCount[ 0 ] >> 3 ) & 0x3F;

    // Update number of bits
    mBitCount[ 0 ] += ( size << 3 );
    if( mBitCount[ 0 ] < ( size << 3 ) ) {
        mBitCount[ 1 ]++;
    }

    mBitCount[ 1 ] += ( size >> 29 );

    partLen = 64 - index;

    // Transform as many times as possible.
    if( size >= partLen ) {
        ::memcpy( mBlock + index, data, partLen );
        transform( mBlock );

        for( i = partLen; i + 63 < size; i += 64 ) {
            transform( ( (uint8_t *) data ) + i );
        }

        index = 0;
    }
    else {
        i = 0;
    }

    // Buffer remaining input
    ::memcpy( mBlock + index, ( (uint8_t *) data ) + i, size - i );
}

/**
 * @copydoc HashingBase::finalize()
 */
void MD5::finalize( ) {
    uint8_t bits[8];
    uint32_t index, padLen;

    // Save number of bits
    encode( bits, mBitCount, 8 );

    // Pad out to 56 mod 64.
    index =  ( mBitCount[ 0 ] >> 3 ) & 0x3f;
    padLen = ( index < 56 ) ? ( 56 - index ) : ( 120 - index );
    update( PADDING, padLen );

    // Append length (before padding)
    update( bits, 8 );

    // Store state in digest
    encode( mHash, mState, 16 );

    // Zeroize sensitive information.
    ::memset( mBlock, 0, sizeof (mBlock ) );
    mBitCount[ 0 ] = 0;
    mBitCount[ 1 ] = 0;

    mState[ 0 ] = 0;
    mState[ 1 ] = 0;
    mState[ 2 ] = 0;
    mState[ 3 ] = 0;
}

/**
 * @brief MD5 basic transformation.
 *
 * Transforms the current state based on the content of the specified block.
 *
 * @param block Data block to process.
 */
void MD5::transform( uint8_t *block ) {
    uint32_t a = mState[ 0 ];
    uint32_t b = mState[ 1 ];
    uint32_t c = mState[ 2 ];
    uint32_t d = mState[ 3 ];
    uint32_t x[16];

    decode( x, block, 64 );

    // Round 1
    FF( a, b, c, d, x[ 0 ], S11, 0xd76aa478 );  // 1
    FF( d, a, b, c, x[ 1 ], S12, 0xe8c7b756 );  // 2
    FF( c, d, a, b, x[ 2 ], S13, 0x242070db );  // 3
    FF( b, c, d, a, x[ 3 ], S14, 0xc1bdceee );  // 4
    FF( a, b, c, d, x[ 4 ], S11, 0xf57c0faf );  // 5
    FF( d, a, b, c, x[ 5 ], S12, 0x4787c62a );  // 6
    FF( c, d, a, b, x[ 6 ], S13, 0xa8304613 );  // 7
    FF( b, c, d, a, x[ 7 ], S14, 0xfd469501 );  // 8
    FF( a, b, c, d, x[ 8 ], S11, 0x698098d8 );  // 9
    FF( d, a, b, c, x[ 9 ], S12, 0x8b44f7af );  // 10
    FF( c, d, a, b, x[ 10 ], S13, 0xffff5bb1 ); // 11
    FF( b, c, d, a, x[ 11 ], S14, 0x895cd7be ); // 12
    FF( a, b, c, d, x[ 12 ], S11, 0x6b901122 ); // 13
    FF( d, a, b, c, x[ 13 ], S12, 0xfd987193 ); // 14
    FF( c, d, a, b, x[ 14 ], S13, 0xa679438e ); // 15
    FF( b, c, d, a, x[ 15 ], S14, 0x49b40821 ); // 16

    // Round 2
    GG( a, b, c, d, x[ 1 ], S21, 0xf61e2562 );  // 17
    GG( d, a, b, c, x[ 6 ], S22, 0xc040b340 );  // 18
    GG( c, d, a, b, x[ 11 ], S23, 0x265e5a51 ); // 19
    GG( b, c, d, a, x[ 0 ], S24, 0xe9b6c7aa );  // 20
    GG( a, b, c, d, x[ 5 ], S21, 0xd62f105d );  // 21
    GG( d, a, b, c, x[ 10 ], S22,  0x2441453 ); // 22
    GG( c, d, a, b, x[ 15 ], S23, 0xd8a1e681 ); // 23
    GG( b, c, d, a, x[ 4 ], S24, 0xe7d3fbc8 );  // 24
    GG( a, b, c, d, x[ 9 ], S21, 0x21e1cde6 );  // 25
    GG( d, a, b, c, x[ 14 ], S22, 0xc33707d6 ); // 26
    GG( c, d, a, b, x[ 3 ], S23, 0xf4d50d87 );  // 27
    GG( b, c, d, a, x[ 8 ], S24, 0x455a14ed );  // 28
    GG( a, b, c, d, x[ 13 ], S21, 0xa9e3e905 ); // 29
    GG( d, a, b, c, x[ 2 ], S22, 0xfcefa3f8 );  // 30
    GG( c, d, a, b, x[ 7 ], S23, 0x676f02d9 );  // 31
    GG( b, c, d, a, x[ 12 ], S24, 0x8d2a4c8a ); // 32

    // Round 3
    HH( a, b, c, d, x[ 5 ], S31, 0xfffa3942 );  // 33
    HH( d, a, b, c, x[ 8 ], S32, 0x8771f681 );  // 34
    HH( c, d, a, b, x[ 11 ], S33, 0x6d9d6122 ); // 35
    HH( b, c, d, a, x[ 14 ], S34, 0xfde5380c ); // 36
    HH( a, b, c, d, x[ 1 ], S31, 0xa4beea44 );  // 37
    HH( d, a, b, c, x[ 4 ], S32, 0x4bdecfa9 );  // 38
    HH( c, d, a, b, x[ 7 ], S33, 0xf6bb4b60 );  // 39
    HH( b, c, d, a, x[ 10 ], S34, 0xbebfbc70 ); // 40
    HH( a, b, c, d, x[ 13 ], S31, 0x289b7ec6 ); // 41
    HH( d, a, b, c, x[ 0 ], S32, 0xeaa127fa );  // 42
    HH( c, d, a, b, x[ 3 ], S33, 0xd4ef3085 );  // 43
    HH( b, c, d, a, x[ 6 ], S34,  0x4881d05 );  // 44
    HH( a, b, c, d, x[ 9 ], S31, 0xd9d4d039 );  // 45
    HH( d, a, b, c, x[ 12 ], S32, 0xe6db99e5 ); // 46
    HH( c, d, a, b, x[ 15 ], S33, 0x1fa27cf8 ); // 47
    HH( b, c, d, a, x[ 2 ], S34, 0xc4ac5665 );  // 48

    // Round 4
    II( a, b, c, d, x[ 0 ], S41, 0xf4292244 );  // 49
    II( d, a, b, c, x[ 7 ], S42, 0x432aff97 );  // 50
    II( c, d, a, b, x[ 14 ], S43, 0xab9423a7 ); // 51
    II( b, c, d, a, x[ 5 ], S44, 0xfc93a039 );  // 52
    II( a, b, c, d, x[ 12 ], S41, 0x655b59c3 ); // 53
    II( d, a, b, c, x[ 3 ], S42, 0x8f0ccc92 );  // 54
    II( c, d, a, b, x[ 10 ], S43, 0xffeff47d ); // 55
    II( b, c, d, a, x[ 1 ], S44, 0x85845dd1 );  // 56
    II( a, b, c, d, x[ 8 ], S41, 0x6fa87e4f );  // 57
    II( d, a, b, c, x[ 15 ], S42, 0xfe2ce6e0 ); // 58
    II( c, d, a, b, x[ 6 ], S43, 0xa3014314 );  // 59
    II( b, c, d, a, x[ 13 ], S44, 0x4e0811a1 ); // 60
    II( a, b, c, d, x[ 4 ], S41, 0xf7537e82 );  // 61
    II( d, a, b, c, x[ 11 ], S42, 0xbd3af235 ); // 62
    II( c, d, a, b, x[ 2 ], S43, 0x2ad7d2bb );  // 63
    II( b, c, d, a, x[ 9 ], S44, 0xeb86d391 );  // 64

    mState[ 0 ] += a;
    mState[ 1 ] += b;
    mState[ 2 ] += c;
    mState[ 3 ] += d;

    // Zeroize sensitive information.
    ::memset( &x, 0, sizeof (x ) );
}

/**
 * @brief Creates a new MD5 handler.
 *
 * @return pointer to the newly created MD5 handler or <tt>null</tt> on error.
 */
void* hash_md5_create( ) {
    return new MD5( );
}

/**
 * @brief Initializes the specified MD5 handler.
 *
 * This function prepares the MD5 handler for hashing data. It must be called
 * prior the first {@link hash_md5_update} or {@link hash_md5_final} calls.
 *
 * @param h Pointer to a valid MD5 handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not valid.
 */
int hash_md5_init( void *h ) {
    int rc = 0;
    MD5 *md5 = dynamic_cast<MD5 *> ( (HashingBase *) h );

    if(  md5 != NULL ) {
        md5->init( );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Updates the specified MD5 handler's state with the data.
 *
 * This function updates the MD5 handler's state by hashing data. It must be
 * called after {@link hash_md5_init} and before {@link hash_md5_final}. The
 * result of calling this function before {@link hash_md5_init} or after {@link
 * hash_md5_final} is undefined.
 *
 * @param h   Pointer to a valid MD5 handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not valid.
 */
int hash_md5_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    MD5 *md5 = dynamic_cast<MD5 *> ( (HashingBase *) h );

    if(  md5 != NULL ) {
        md5->update( buf, len );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Finalizes the specified MD5 handler's state.
 *
 * This function finalizes the MD5 handler's state and returns the hashing
 * value. It must be called after {@link hash_md5_init} The result of calling
 * this function before {@link hash_md5_init} is undefined.
 *
 * @param h   Pointer to a valid MD5 handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not valid.
 */
int hash_md5_finalize( void *h ) {
    int rc = 0;
    MD5 *md5 = dynamic_cast<MD5 *> ( (HashingBase *) h );

    if(  md5 != NULL ) {
        rc = 1;
        md5->finalize( );
    }

    return rc;
}

/**
 * @brief Retrieves the hashing value after the last <tt>hash_md5_finalize</tt>
 *        function call.
 *
 * The result of calling this method prior to the {@link hash_md5_finalize}
 * method is undefined. If the memory buffer is smaller than the hash size, only
 * the higher part of the hash value is returned.
 *
 * If <tt>h</tt> is not a valid MD5 handler, the function returns immediately.
 *
 * @param h   Pointer to a valid MD5 handler.
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int hash_md5_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    MD5 *md5 = dynamic_cast<MD5 *> ( (HashingBase *) h );

    if(  md5 != NULL ) {
        rc = md5->getValue( buf, len );
    }

    return rc;
}

/**
 * Destroys an existing MD5 handler.
 *
 * @param h Pointer to a valid MD5 handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 on error.
 */
int hash_md5_destroy( void *h ) {
    int rc = 0;
    MD5 *md5 = dynamic_cast<MD5 *> ( (HashingBase *) h );

    if(  md5 != NULL ) {
        rc = 1;
        delete md5;
    }

    return rc;
}

// EOF: md5.cpp