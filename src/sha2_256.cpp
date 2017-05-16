// ////////////////////////////////////////////////////////////////////////////
// System:     libHash
// File:       sha2_256.cpp
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-24
//
// Description
// Implementation of SHA-2 256-bits hashing algorithm
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

#define Sha256SIGMA0( x )    ( ROTR( (x),  2, 32 ) ^ ROTR( (x), 13, 32 ) ^  ROTR( (x), 22, 32 ))
#define Sha256SIGMA1( x )    ( ROTR( (x),  6, 32 ) ^ ROTR( (x), 11, 32 ) ^  ROTR( (x), 25, 32 ))
#define Sha256sigma0( x )    ( ROTR( (x),  7, 32 ) ^ ROTR( (x), 18, 32 ) ^ ( (x) >> 3 ))
#define Sha256sigma1( x )    ( ROTR( (x), 17, 32 ) ^ ROTR( (x), 19, 32 ) ^ ( (x) >> 10 ))

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

// SHA2-256 constants
const uint32_t KSha256[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

/* ------------------------------------------------------------------------- */
void SHA2_256::init() {
    // Initial context state
    mState[ 0 ] = 0x6a09e667;
    mState[ 1 ] = 0xbb67ae85;
    mState[ 2 ] = 0x3c6ef372;
    mState[ 3 ] = 0xa54ff53a;
    mState[ 4 ] = 0x510e527f;
    mState[ 5 ] = 0x9b05688c;
    mState[ 6 ] = 0x1f83d9ab;
    mState[ 7 ] = 0x5be0cd19;

    mBitCount =0;
    mIndex = 0;
}

/* ------------------------------------------------------------------------- */

void SHA2_256::update( const void *data, size_t size ) {
    uint32_t i;

    // Update number of bits
    mBitCount += size << 3;

    for(i = 0; i < size; i++ ) { 
        mBlock[mIndex++] = ((uint8_t *)data)[i];
        if( mIndex == 64 ) { 
            transform();
            mIndex = 0;
        }
    }
}

/* ------------------------------------------------------------------------- */

void SHA2_256::finalize() {
    int32_t i;

    // Make sure the message is a multiple 512-bits
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
        // There is enough room for the padding bit and the message length
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
    mBlock[ 63 ] = (uint8_t)  ( mBitCount & 0x00000000000000FF );

    // Transform the last message block
    transform();

    // Copy the digest number in the resulting buffer. The resulting
    // hash is big-endian
    for( i = 0; i < 8; i++ ) {
        mHash[ ( i * 4 ) ] = (uint8_t) (( mState[ i ] & 0xFF000000 ) >> 24 );
        mHash[ ( i * 4 ) + 1 ] = (uint8_t) (( mState[ i ] & 0x00FF0000 ) >> 16 );
        mHash[ ( i * 4 ) + 2 ] = (uint8_t) (( mState[ i ] & 0x0000FF00 ) >> 8 );
        mHash[ ( i * 4 ) + 3 ] = (uint8_t)  ( mState[ i ] & 0x000000FF );
    }

    // Clear sensitive information
    clear();
}

/* ------------------------------------------------------------------------- */

void SHA2_256::clear() {
    ::memset( mState, 0, sizeof( mState) );
    ::memset( mBlock, 0, sizeof( mBlock ) );
    mIndex = 0;
    mBitCount = 0;
}

/* ------------------------------------------------------------------------- */

void SHA2_256::transform() {
    uint32_t tmp1, tmp2;
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;  // Working variables
    int32_t  t;

    // Prepare the buffer schedule
    for( t = 0; t < 16; t++ ) {
        W[ t ] = mBlock[ t * 4    ] << 24 |
                 mBlock[ t * 4 + 1 ] << 16 |
                 mBlock[ t * 4 + 2 ] <<  8 |
                 mBlock[ t * 4 + 3 ];
    }

    for( t = 16; t < 64; t++ ) {
        W[ t ] = Sha256sigma1( W[ t - 2 ] ) + W[ t - 7 ] + Sha256sigma0( W[ t - 15 ] ) + W[ t - 16 ];
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

    // Rounds 0 to 63
    for( t = 0; t < 64; t++ ) {
        tmp1 = h + Sha256SIGMA1( e ) + CH( e, f, g ) + KSha256[ t ] + W[ t ];
        tmp2 = Sha256SIGMA0( a ) + MAJ( a, b, c );
        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

    // Update the context current state
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

void* hash_sha2_256_create() {
    return new SHA2_256();
}

// -------------------------------------------------------------------------

int hash_sha2_256_init( void *h ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->init();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_256_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->update( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_256_finalize( void *h ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->finalize();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_256_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = sha->getValue( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_256_destroy( void *h ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        delete sha;
    }

    return rc;
}

// EOF: sha2_256.cpp

