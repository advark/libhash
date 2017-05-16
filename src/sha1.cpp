// ////////////////////////////////////////////////////////////////////////////
// System:     libHash
// File:       sha1.cpp
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-21
//
// Description
// Implementation of SHA-1 family algorithms
//
// Copyright (c) 2017, Yanick Poirier. All rights reserved.
// ////////////////////////////////////////////////////////////////////////////

// ============================================================================
// HEADER FILES
// ============================================================================

#include <stdlib.h>
#include <string.h>
#include "../include/libhash/sha1.h"

using namespace libhash;

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

// Helper macro functions for SHA transformation
#define CH( x, y, z )           (( (x) & (y) ) ^ ((~(x)) & (z)))
#define PARITY( x, y, z )       ( (x) ^ (y) ^ (z) )
#define MAJ( x, y, z )          (( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ))

// ============================================================================
// STRUCTURES & TYPEDEFS
// ============================================================================

// ============================================================================
// CLASSES
// ============================================================================

// ============================================================================
// PROTOTYPES
// ============================================================================

// ============================================================================
// IMPLEMENTATION
// ============================================================================

// SHA-1 constants
uint32_t KSha1[]   = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

/* ------------------------------------------------------------------------- */
void SHA1::init() {
    // Initial state values
    mState[ 0 ] = 0x67452301;
    mState[ 1 ] = 0xefcdab89;
    mState[ 2 ] = 0x98badcfe;
    mState[ 3 ] = 0x10325476;
    mState[ 4 ] = 0xc3d2e1f0;

    mBitCount = 0;
    mIndex = 0;
}

/* ------------------------------------------------------------------------- */

void SHA1::update( const void *data, size_t size ) {
    uint32_t i;

    // Update number of bits
    mBitCount += size << 3;

    for( i = 0; i < size; i++ ) {
        mBlock[ mIndex++ ] = ( (uint8_t *) data)[ i ];
        if( mIndex == 64 ) {
            transform();
            mIndex = 0;
        }
    }
}

/* ------------------------------------------------------------------------- */

void SHA1::finalize() {
    if( mIndex > 55 ) {
        if( mIndex < 64 ) {
            // Not enough room to hold the padding bit and mesage length. So
            // we pad the block, process it and continue padding on a
            // second block.
            mBlock[ mIndex ] = (uint8_t) 0x80;
            mIndex++;
            ::memset( mBlock + mIndex, 0, 64 - mIndex );

            transform();

            // Pad only 56 bytes on the second block. The last 8 will be
            // filled later with the message length.
            ::memset( mBlock, 0, 56 );
        }
        else {
            transform();

            mBlock[ 0 ] = 0x80;
            ::memset( mBlock + 1, 0, 55 );
        }
    }
    else {
        // There is enough room for the padding bits and the message
        // length
        mBlock[ mIndex ] = (uint8_t) 0x80;
        mIndex++;
        ::memset( mBlock + mIndex, 0, 56 - mIndex );
    }

    // Store the message length the in last 64 bits (8 bytes)
    mBlock[ 56 ] = (uint8_t) (( mBitCount & 0xFF00000000000000 ) >> 56 );
    mBlock[ 57 ] = (uint8_t) (( mBitCount & 0x00FF000000000000 ) >> 48 );
    mBlock[ 58 ] = (uint8_t) (( mBitCount & 0x0000FF0000000000 ) >> 40 );
    mBlock[ 59 ] = (uint8_t) (( mBitCount & 0x000000FF00000000 ) >> 32 );
    mBlock[ 60 ] = (uint8_t) (( mBitCount & 0x00000000FF000000 ) >> 24 );
    mBlock[ 61 ] = (uint8_t) (( mBitCount & 0x0000000000FF0000 ) >> 16 );
    mBlock[ 62 ] = (uint8_t) (( mBitCount & 0x000000000000FF00 ) >> 8 );
    mBlock[ 63 ] = (uint8_t) ( mBitCount & 0x00000000000000FF );

    // Transform the last message block
    transform();

    // Copy the digest number in the resulting buffer. The resulting
    // digest is big-endian
    for( int i = 0; i < 5; i++ ) {
        mHash[ ( i * 4 ) ] = (uint8_t) (( mState[ i ] & 0xFF000000 ) >> 24 );
        mHash[ ( i * 4 ) + 1 ] = (uint8_t) (( mState[ i ] & 0x00FF0000 ) >> 16 );
        mHash[ ( i * 4 ) + 2 ] = (uint8_t) (( mState[ i ] & 0x0000FF00 ) >> 8 );
        mHash[ ( i * 4 ) + 3 ] = (uint8_t)  ( mState[ i ] & 0x000000FF );
    }

    // Clear sensitive information
    ::memset( mState, 0, sizeof(mState) );
    ::memset( mBlock, 0, sizeof(mBlock) );
    mIndex = 0;
    mBitCount = 0;
}

/* ------------------------------------------------------------------------- */

void SHA1::transform() {
    uint32_t tmp;
    uint32_t W[80];
    uint32_t a, b, c, d, e;  // Working variables
    int32_t  t;

    // Prepare the buffer schedule
    for( t = 0; t < 16; t++ ) {
        W[ t ] = ( mBlock[ t * 4 ] << 24 ) |
                 ( mBlock[ (t * 4) + 1 ] << 16 ) |
                 ( mBlock[ (t * 4) + 2 ] << 8 ) |
                 mBlock[ (t * 4) + 3 ];
    }

    for( t = 16; t < 80; t++ ) {
        tmp = W[ t - 3 ] ^ W[ t - 8 ] ^ W[ t - 14 ] ^ W[ t - 16 ];
        W[ t ] = ROTL( tmp, 1, 32 );
    }

    // Initialize working variables
    a = mState[ 0 ];
    b = mState[ 1 ];
    c = mState[ 2 ];
    d = mState[ 3 ];
    e = mState[ 4 ];

    // Rounds 0 to 19
    for( t = 0; t < 20; t++ ) {
        tmp = ROTL( a, 5, 32 ) + CH( b, c, d ) + e + KSha1[ 0 ] + W[ t ];
        e = d;
        d = c;
        c = ROTL( b, 30, 32 );
        b = a;
        a = tmp;
    }

    // Rounds 20 to 39
    for( t = 20; t < 40; t++ ) {
        tmp = ROTL( a, 5, 32 ) + PARITY( b, c, d ) + e + KSha1[ 1 ] + W[ t ];
        e = d;
        d = c;
        c = ROTL( b, 30, 32 );
        b = a;
        a = tmp;
    }

    // Rounds 40 to 59
    for( t = 40; t < 60; t++ ) {
        tmp = ROTL( a, 5, 32 ) + MAJ( b, c, d ) + e + KSha1[ 2 ] + W[ t ];
        e = d;
        d = c;
        c = ROTL( b, 30, 32 );
        b = a;
        a = tmp;
    }

    // Rounds 60 to 79
    for( t = 60; t < 80; t++ ) {
        tmp = ROTL( a,  5, 32 ) + PARITY( b, c, d ) + e + KSha1[ 3 ] + W[ t ];
        e = d;
        d = c;
        c = ROTL( b, 30, 32 );
        b = a;
        a = tmp;
    }

    // Update the state of the context
    mState[ 0 ] += a;
    mState[ 1 ] += b;
    mState[ 2 ] += c;
    mState[ 3 ] += d;
    mState[ 4 ] += e;

    // Reset the current block index
    mIndex = 0;
}

// -------------------------------------------------------------------------

void* hash_sha1_create() {
    return new SHA1();
}

// -------------------------------------------------------------------------

int hash_sha1_init( void *h ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = 1;
        sha1->init();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha1_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = 1;
        sha1->update( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha1_finalize( void *h ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = 1;
        sha1->finalize();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha1_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = sha1->getValue( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha1_destroy( void *h ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = 1;
        delete sha1;
    }

    return rc;
}

// EOF: sha1.cpp

