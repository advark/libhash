// ////////////////////////////////////////////////////////////////////////////
// System:     libHash
// File:       sha2_512.cpp
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-24
//
// Description
// Implementation of SHA-2 512-bits hashing algorithm
//
// Copyright (c) 2017, Yanick Poirier. All rights reserved.
// ////////////////////////////////////////////////////////////////////////////

// ============================================================================
// HEADER FILES
// ============================================================================

#include <stdlib.h>
#include <string.h>
#include "../include/libhash/defs.h"
#include "../include/libhash/hashbase.h"
#include "../include/libhash/sha2.h"

using namespace libhash;

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

// Helper macro functions for SHA transformation
#define CH( x, y, z )       (( (x) & (y) ) ^ ((~(x)) & (z)))
#define MAJ( x, y, z )      (( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ))

#define Sha512SIGMA0( x )    ( ROTR( (x), 28, 64 ) ^ ROTR( (x), 34, 64 ) ^ ROTR( (x), 39, 64 ))
#define Sha512SIGMA1( x )    ( ROTR( (x), 14, 64 ) ^ ROTR( (x), 18, 64 ) ^ ROTR( (x), 41, 64 ))
#define Sha512sigma0( x )    ( ROTR( (x),  1, 64 ) ^ ROTR( (x),  8, 64 ) ^ ( (x) >> 7 ))
#define Sha512sigma1( x )    ( ROTR( (x), 19, 64 ) ^ ROTR( (x), 61, 64 ) ^ ( (x) >> 6 ))

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

// SHA2-512 constants
const uint64_t KSha512[80] = { 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };

/* ------------------------------------------------------------------------- */
void SHA2_512::init() {
    // Initial context state
    mState[ 0 ] = 0x6a09e667f3bcc908L;
    mState[ 1 ] = 0xbb67ae8584caa73bL;
    mState[ 2 ] = 0x3c6ef372fe94f82bL;
    mState[ 3 ] = 0xa54ff53a5f1d36f1L;
    mState[ 4 ] = 0x510e527fade682d1L;
    mState[ 5 ] = 0x9b05688c2b3e6c1fL;
    mState[ 6 ] = 0x1f83d9abfb41bd6bL;
    mState[ 7 ] = 0x5be0cd19137e2179L;

    mBitCount[ 0 ] = 0;
    mBitCount[ 1 ] = 0;
    mIndex = 0;
}

/* ------------------------------------------------------------------------- */

void SHA2_512::update( const void *data, size_t size ) {
    uint32_t i;

    // Update number of bits
    mBitCount[ 0 ] += (( size & 0xffffffff00000000L ) >> 29 );
    mBitCount[ 1 ] += ( size & 0x00000000ffffffffL ) << 3;
    mBitCount[ 1 ] += (mBitCount[ 0 ] & 0xffffffff00000000L ) >> 32;
    mBitCount[ 0 ] &= 0x00000000ffffffffL;

    for(i = 0; i < size; i++ ) { 
        mBlock[mIndex++] = ((uint8_t *)data)[i];
        if( mIndex == 128 ) { 
            transform();
            mIndex = 0;
        }
    }
}

/* ------------------------------------------------------------------------- */

void SHA2_512::finalize() {
    int32_t i;

    // Make sure the message is a multiple 512-bits
    if( mIndex > 111 ) {
        if( mIndex < 128 ) {
            // Not enough room to hold the padding bit and mesage length. So
            // we pad the block, process it and continue padding on a
            // second block
            mBlock[ mIndex ] = (uint8_t) 0x80;
            mIndex++;
            ::memset( mBlock + mIndex, 0, 128 - mIndex );

            transform();

            // Pad only 112 bytes on the second block. The last 16 will be
            // filled later with the message length.
            ::memset( mBlock, 0, 112 );
        }
        else {
            // Not enough room and the buffer is already full
            transform();

            mBlock[ 0 ] = 0x80;
            ::memset( mBlock + 1, 0, 111 );
        }
    }
    else {
        // There is enough room for the padding bit and the message length
        mBlock[ mIndex ] = (uint8_t) 0x80;
        mIndex++;
        ::memset( mBlock + mIndex, 0, 112 - mIndex );
    }

    // Store the message length the in last 128 bits (16 bytes)
    mBlock[ 112 ] = (uint8_t) (( mBitCount[ 0 ] & 0xff00000000000000L ) >> 56 );
    mBlock[ 113 ] = (uint8_t) (( mBitCount[ 0 ] & 0x00ff000000000000L ) >> 48 );
    mBlock[ 114 ] = (uint8_t) (( mBitCount[ 0 ] & 0x0000ff0000000000L ) >> 40 );
    mBlock[ 115 ] = (uint8_t) (( mBitCount[ 0 ] & 0x000000ff00000000L ) >> 32 );
    mBlock[ 116 ] = (uint8_t) (( mBitCount[ 0 ] & 0x00000000ff000000L ) >> 24 );
    mBlock[ 117 ] = (uint8_t) (( mBitCount[ 0 ] & 0x0000000000ff0000L ) >> 16 );
    mBlock[ 118 ] = (uint8_t) (( mBitCount[ 0 ] & 0x000000000000ff00L ) >> 8 );
    mBlock[ 119 ] = (uint8_t)  ( mBitCount[ 0 ] & 0x00000000000000ffL );
    mBlock[ 120 ] = (uint8_t) (( mBitCount[ 1 ] & 0xff00000000000000L ) >> 56 );
    mBlock[ 121 ] = (uint8_t) (( mBitCount[ 1 ] & 0x00ff000000000000L ) >> 48 );
    mBlock[ 122 ] = (uint8_t) (( mBitCount[ 1 ] & 0x0000ff0000000000L ) >> 40 );
    mBlock[ 123 ] = (uint8_t) (( mBitCount[ 1 ] & 0x000000ff00000000L ) >> 32 );
    mBlock[ 124 ] = (uint8_t) (( mBitCount[ 1 ] & 0x00000000ff000000L ) >> 24 );
    mBlock[ 125 ] = (uint8_t) (( mBitCount[ 1 ] & 0x0000000000ff0000L ) >> 16 );
    mBlock[ 126 ] = (uint8_t) (( mBitCount[ 1 ] & 0x000000000000ff00L ) >> 8 );
    mBlock[ 127 ] = (uint8_t)  ( mBitCount[ 1 ] & 0x00000000000000ffL );

    // Transform the last message block
    transform();

    // Copy the digest number in the resulting buffer. The resulting
    // digest is big-endian.
    for( i = 0; i < 8; i++ ) {
        mHash[ ( i * 8 ) ] = (uint8_t) (( mState[ i ] & 0xff00000000000000L ) >> 56 );
        mHash[ ( i * 8 ) + 1 ] = (uint8_t) (( mState[ i ] & 0x00ff000000000000L ) >> 48 );
        mHash[ ( i * 8 ) + 2 ] = (uint8_t) (( mState[ i ] & 0x0000ff0000000000L ) >> 40 );
        mHash[ ( i * 8 ) + 3 ] = (uint8_t) (( mState[ i ] & 0x000000ff00000000L ) >> 32 );
        mHash[ ( i * 8 ) + 4 ] = (uint8_t) (( mState[ i ] & 0x00000000ff000000L ) >> 24 );
        mHash[ ( i * 8 ) + 5 ] = (uint8_t) (( mState[ i ] & 0x0000000000ff0000L ) >> 16 );
        mHash[ ( i * 8 ) + 6 ] = (uint8_t) (( mState[ i ] & 0x000000000000ff00L ) >> 8 );
        mHash[ ( i * 8 ) + 7 ] = (uint8_t)  ( mState[ i ] & 0x00000000000000ffL );
    }

    // Clear sensitive information
    clear();
}

/* ------------------------------------------------------------------------- */

void SHA2_512::clear() {
    ::memset( mBlock, 0, sizeof( mBlock ) );
    ::memset( mBitCount, 0, sizeof( mBitCount) );
    ::memset( mState, 0, sizeof( mState ) );
    mIndex = 0;
}

/* ------------------------------------------------------------------------- */

void SHA2_512::transform() {
    uint64_t tmp1, tmp2;
    uint64_t  W[80];
    uint64_t  a, b, c, d, e, f, g, h;  /* Working variables */
    int32_t   i;

    /* Prepare the buffer schedule */
    for( i = 0; i < 16; i++ ) {
        W[ i ] = ( (uint64_t) mBlock[ i * 8    ] << 56 ) |
                 ( (uint64_t) mBlock[ i * 8 + 1 ] << 48 ) |
                 ( (uint64_t) mBlock[ i * 8 + 2 ] << 40 ) |
                 ( (uint64_t) mBlock[ i * 8 + 3 ] << 32 ) |
                 ( (uint64_t) mBlock[ i * 8 + 4 ] << 24 ) |
                 ( (uint64_t) mBlock[ i * 8 + 5 ] << 16 ) |
                 ( (uint64_t) mBlock[ i * 8 + 6 ] <<  8 ) |
                 ( (uint64_t) mBlock[ i * 8 + 7 ]);
    }

    for( i = 16; i < 80; i++ ) {
        W[ i ] = Sha512sigma1( W[ i - 2 ] ) + W[ i - 7 ] + Sha512sigma0( W[ i - 15 ] ) + W[ i - 16 ];
    }

    // Initialize working variables
    a = mState[ 0 ];
    b = mState[ 1 ];
    c = mState[ 2 ];
    d = mState[ 3 ];
    e = mState[ 4 ];
    f = mState[ 5 ];
    g = mState[ 6 ];
    h = mState[ 7 ];

    // Rounds 0 to 79
    for( i = 0; i < 80; i++ ) {
        tmp1 = h + Sha512SIGMA1( e ) + CH( e, f, g ) + KSha512[ i ] + W[ i ];
        tmp2 = Sha512SIGMA0( a ) + MAJ( a, b, c );
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

    /* Update the context current state */
    mState[ 0 ] += a;
    mState[ 1 ] += b;
    mState[ 2 ] += c;
    mState[ 3 ] += d;
    mState[ 4 ] += e;
    mState[ 5 ] += f;
    mState[ 6 ] += g;
    mState[ 7 ] += h;

    // Reset the current block index
    mIndex = 0;
}


// -------------------------------------------------------------------------

void* hash_sha2_512_create() {
    return new SHA2_512();
}

// -------------------------------------------------------------------------

int hash_sha2_512_init( void *h ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->init();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_512_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->update( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_512_finalize( void *h ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->finalize();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_512_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = sha->getValue( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_512_destroy( void *h ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        delete sha;
    }

    return rc;
}

// EOF: sha2_512.cpp

