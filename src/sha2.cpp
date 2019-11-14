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
// File:       sha2.cpp
//
// Author:     Yanick Poirier
// Date:       2017-01-24
//
// Description
// Implementation of SHA-2 family algorithms.
//=============================================================================

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>
#include "../include/libhash/defs.h"
#include "../include/libhash/hashbase.h"
#include "../include/libhash/sha2.h"

using namespace libhash;

//-----------------------------------------------------------------------------
// CONSTANTS & MACROS
//-----------------------------------------------------------------------------

// Helper macro functions for SHA transformation
#define CH( x, y, z )       (( (x) & (y) ) ^ ((~(x)) & (z)))
#define MAJ( x, y, z )      (( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ))

#define Sha256SIGMA0( x )    ( ROTR( (x),  2, 32 ) ^ ROTR( (x), 13, 32 ) ^  ROTR( (x), 22, 32 ))
#define Sha256SIGMA1( x )    ( ROTR( (x),  6, 32 ) ^ ROTR( (x), 11, 32 ) ^  ROTR( (x), 25, 32 ))
#define Sha256sigma0( x )    ( ROTR( (x),  7, 32 ) ^ ROTR( (x), 18, 32 ) ^ ( (x) >> 3 ))
#define Sha256sigma1( x )    ( ROTR( (x), 17, 32 ) ^ ROTR( (x), 19, 32 ) ^ ( (x) >> 10 ))

#define Sha512SIGMA0( x )    ( ROTR( (x), 28, 64 ) ^ ROTR( (x), 34, 64 ) ^ ROTR( (x), 39, 64 ))
#define Sha512SIGMA1( x )    ( ROTR( (x), 14, 64 ) ^ ROTR( (x), 18, 64 ) ^ ROTR( (x), 41, 64 ))
#define Sha512sigma0( x )    ( ROTR( (x),  1, 64 ) ^ ROTR( (x),  8, 64 ) ^ ( (x) >> 7 ))
#define Sha512sigma1( x )    ( ROTR( (x), 19, 64 ) ^ ROTR( (x), 61, 64 ) ^ ( (x) >> 6 ))

// SHA2-256 constants
const uint32_t KSha256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA2-512 constants
const uint64_t KSha512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
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
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

//-----------------------------------------------------------------------------
// STRUCTURES & TYPEDEFS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// IMPLEMENTATION
//-----------------------------------------------------------------------------

//=== SHA-224 implementation ==================================================

/**
 * @copydoc HashingBase::init()
 */
void SHA2_224::init( ) {
    // Initial context state
    mState[ 0 ] = 0xc1059ed8;
    mState[ 1 ] = 0x367cd507;
    mState[ 2 ] = 0x3070dd17;
    mState[ 3 ] = 0xf70e5939;
    mState[ 4 ] = 0xffc00b31;
    mState[ 5 ] = 0x68581511;
    mState[ 6 ] = 0x64f98fa7;
    mState[ 7 ] = 0xbefa4fa4;

    mBitCount = 0;
    mIndex = 0;
}

/**
 * @copydoc HashingBase::finalize()
 */
void SHA2_224::finalize( ) {
    int32_t i;

    // Pad the last message block
    pad( );

    // Copy the digest number in the resulting buffer. The resulting
    // hash is big-endian
    for( i = 0; i < 7; i++ ) {
        mHash[ ( i * 4 ) ] = (uint8_t) ( ( mState[ i ] & 0xff000000 ) >> 24 );
        mHash[ ( i * 4 ) + 1 ] = (uint8_t) ( ( mState[ i ] & 0x00ff0000 ) >> 16 );
        mHash[ ( i * 4 ) + 2 ] = (uint8_t) ( ( mState[ i ] & 0x0000ff00 ) >> 8 );
        mHash[ ( i * 4 ) + 3 ] = (uint8_t)  ( mState[ i ] & 0x000000ff );
    }

    // Clear sensitive information
    clear( );
}

void* hash_sha2_224_create( ) {
    return new SHA2_256( );
}

int hash_sha2_224_init( void *h ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->init( );
    }

    return rc;
}

int hash_sha2_224_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->update( buf, len );
    }

    return rc;
}

int hash_sha2_224_finalize( void *h ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->finalize( );
    }

    return rc;
}

int hash_sha2_224_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = sha->getValue( buf, len );
    }

    return rc;
}

int hash_sha2_224_destroy( void *h ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        delete sha;
    }

    return rc;
}

//=== SHA-256 implementation ==================================================

/**
 * @copydoc HashingBase::init()
 */
void SHA2_256::init( ) {
    // Initial context state
    mState[ 0 ] = 0x6a09e667;
    mState[ 1 ] = 0xbb67ae85;
    mState[ 2 ] = 0x3c6ef372;
    mState[ 3 ] = 0xa54ff53a;
    mState[ 4 ] = 0x510e527f;
    mState[ 5 ] = 0x9b05688c;
    mState[ 6 ] = 0x1f83d9ab;
    mState[ 7 ] = 0x5be0cd19;

    mBitCount = 0;
    mIndex = 0;
}

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void SHA2_256::update( const void *data, size_t size ) {
    size_t i;

    // Update number of bits
    mBitCount += size << 3;

    for( i = 0; i < size; i++ ) {
        mBlock[mIndex++] = ( (uint8_t *) data )[i];
        if( mIndex == 64 ) {
            transform( );
            mIndex = 0;
        }
    }
}

void SHA2_256::pad( ) {
    // Make sure the message is a multiple 512-bits
    if( mIndex > 55 ) {
        if( mIndex < 64 ) {
            // Not enough room to hold the padding bit and mesage length. So
            // we pad the block, process it and continue padding on a
            // second block.
            mBlock[ mIndex ] = (uint8_t) 0x80;
            mIndex++;
            ::memset( mBlock + mIndex, 0, 64 - mIndex );

            transform( );

            // Pad only 56 bytes on the second block. The last 8 will be
            // filled later with the message length.
            ::memset( mBlock, 0, 56 );
        }
        else {
            transform( );

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
    mBlock[ 56 ] = (uint8_t) ( ( mBitCount & 0xFF00000000000000 ) >> 56 );
    mBlock[ 57 ] = (uint8_t) ( ( mBitCount & 0x00FF000000000000 ) >> 48 );
    mBlock[ 58 ] = (uint8_t) ( ( mBitCount & 0x0000FF0000000000 ) >> 40 );
    mBlock[ 59 ] = (uint8_t) ( ( mBitCount & 0x000000FF00000000 ) >> 32 );
    mBlock[ 60 ] = (uint8_t) ( ( mBitCount & 0x00000000FF000000 ) >> 24 );
    mBlock[ 61 ] = (uint8_t) ( ( mBitCount & 0x0000000000FF0000 ) >> 16 );
    mBlock[ 62 ] = (uint8_t) ( ( mBitCount & 0x000000000000FF00 ) >> 8 );
    mBlock[ 63 ] = (uint8_t)  ( mBitCount & 0x00000000000000FF );

    // Transform the last message block
    transform( );
}

/**
 * @copydoc HashingBase::finalize()
 */
void SHA2_256::finalize( ) {
    int32_t i;

    // Pad the last message block
    pad( );

    // Copy the digest number in the resulting buffer. The resulting
    // hash is big-endian
    for( i = 0; i < 8; i++ ) {
        mHash[ ( i * 4 ) ] = (uint8_t) ( ( mState[ i ] & 0xFF000000 ) >> 24 );
        mHash[ ( i * 4 ) + 1 ] = (uint8_t) ( ( mState[ i ] & 0x00FF0000 ) >> 16 );
        mHash[ ( i * 4 ) + 2 ] = (uint8_t) ( ( mState[ i ] & 0x0000FF00 ) >> 8 );
        mHash[ ( i * 4 ) + 3 ] = (uint8_t)  ( mState[ i ] & 0x000000FF );
    }

    // Clear sensitive information
    clear( );
}

/**
 * Clears internal data after finalization.
 */
void SHA2_256::clear( ) {
    ::memset( mState, 0, sizeof ( mState ) );
    ::memset( mBlock, 0, sizeof ( mBlock ) );
    mIndex = 0;
    mBitCount = 0;
}

/**
 * Transformation rounds.
 */
void SHA2_256::transform( ) {
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

void* hash_sha2_256_create( ) {
    return new SHA2_256( );
}

int hash_sha2_256_init( void *h ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->init( );
    }

    return rc;
}

int hash_sha2_256_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->update( buf, len );
    }

    return rc;
}

int hash_sha2_256_finalize( void *h ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->finalize( );
    }

    return rc;
}

int hash_sha2_256_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = sha->getValue( buf, len );
    }

    return rc;
}

int hash_sha2_256_destroy( void *h ) {
    int rc = 0;
    SHA2_256 *sha = dynamic_cast<SHA2_256 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        delete sha;
    }

    return rc;
}

//=== SHA-384 implementation ==================================================

/**
 * @copydoc HashingBase::init()
 */
void SHA2_384::init( ) {
    // Initial context state
    mState[ 0 ] = 0xcbbb9d5dc1059ed8L;
    mState[ 1 ] = 0x629a292a367cd507L;
    mState[ 2 ] = 0x9159015a3070dd17L;
    mState[ 3 ] = 0x152fecd8f70e5939L;
    mState[ 4 ] = 0x67332667ffc00b31L;
    mState[ 5 ] = 0x8eb44a8768581511L;
    mState[ 6 ] = 0xdb0c2e0d64f98fa7L;
    mState[ 7 ] = 0x47b5481dbefa4fa4L;

    mBitCount[ 0 ] = 0;
    mBitCount[ 1 ] = 0;
    mIndex = 0;
}

/**
 * @copydoc HashingBase::finalize()
 */
void SHA2_384::finalize( ) {
    int32_t i;

    // Pad the last message block
    pad( );

    // Copy the digest number in the resulting buffer. The resulting digest is big-endian.
    for( i = 0; i < 6; i++ ) {
        mHash[ ( i * 8 ) ] = (uint8_t) ( ( mState[ i ] & 0xff00000000000000L ) >> 56 );
        mHash[ ( i * 8 ) + 1 ] = (uint8_t) ( ( mState[ i ] & 0x00ff000000000000L ) >> 48 );
        mHash[ ( i * 8 ) + 2 ] = (uint8_t) ( ( mState[ i ] & 0x0000ff0000000000L ) >> 40 );
        mHash[ ( i * 8 ) + 3 ] = (uint8_t) ( ( mState[ i ] & 0x000000ff00000000L ) >> 32 );
        mHash[ ( i * 8 ) + 4 ] = (uint8_t) ( ( mState[ i ] & 0x00000000ff000000L ) >> 24 );
        mHash[ ( i * 8 ) + 5 ] = (uint8_t) ( ( mState[ i ] & 0x0000000000ff0000L ) >> 16 );
        mHash[ ( i * 8 ) + 6 ] = (uint8_t) ( ( mState[ i ] & 0x000000000000ff00L ) >> 8 );
        mHash[ ( i * 8 ) + 7 ] = (uint8_t) ( ( mState[ i ] & 0x00000000000000ffL ) );
    }

    // Clear sensitive information
    clear( );
}

void* hash_sha2_384_create( ) {
    return new SHA2_384( );
}

int hash_sha2_384_init( void *h ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->init( );
    }

    return rc;
}

int hash_sha2_384_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->update( buf, len );
    }

    return rc;
}

int hash_sha2_384_finalize( void *h ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->finalize( );
    }

    return rc;
}

int hash_sha2_384_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = sha->getValue( buf, len );
    }

    return rc;
}

int hash_sha2_384_destroy( void *h ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        delete sha;
    }

    return rc;
}

//=== SHA-512 implementation ==================================================

/**
 * @copydoc HashingBase::init()
 */
void SHA2_512::init( ) {
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

void SHA2_512::update( const void *data, size_t size ) {
    size_t i;

    // Update number of bits
    mBitCount[ 0 ] += ( ( size & 0xffffffff00000000L ) >> 29 );
    mBitCount[ 1 ] += ( size & 0x00000000ffffffffL ) << 3;
    mBitCount[ 1 ] += ( mBitCount[ 0 ] & 0xffffffff00000000L ) >> 32;
    mBitCount[ 0 ] &= 0x00000000ffffffffL;

    for( i = 0; i < size; i++ ) {
        mBlock[mIndex++] = ( (uint8_t *) data )[i];
        if( mIndex == 128 ) {
            transform( );
            mIndex = 0;
        }
    }
}

void SHA2_512::pad( ) {
    // Make sure the message is a multiple 512-bits
    if( mIndex > 111 ) {
        if( mIndex < 128 ) {
            // Not enough room to hold the padding bit and mesage length. So
            // we pad the block, process it and continue padding on a
            // second block
            mBlock[ mIndex ] = (uint8_t) 0x80;
            mIndex++;
            ::memset( mBlock + mIndex, 0, 128 - mIndex );

            transform( );

            // Pad only 112 bytes on the second block. The last 16 will be
            // filled later with the message length.
            ::memset( mBlock, 0, 112 );
        }
        else {
            // Not enough room and the buffer is already full
            transform( );

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
    mBlock[ 112 ] = (uint8_t) ( ( mBitCount[ 0 ] & 0xff00000000000000L ) >> 56 );
    mBlock[ 113 ] = (uint8_t) ( ( mBitCount[ 0 ] & 0x00ff000000000000L ) >> 48 );
    mBlock[ 114 ] = (uint8_t) ( ( mBitCount[ 0 ] & 0x0000ff0000000000L ) >> 40 );
    mBlock[ 115 ] = (uint8_t) ( ( mBitCount[ 0 ] & 0x000000ff00000000L ) >> 32 );
    mBlock[ 116 ] = (uint8_t) ( ( mBitCount[ 0 ] & 0x00000000ff000000L ) >> 24 );
    mBlock[ 117 ] = (uint8_t) ( ( mBitCount[ 0 ] & 0x0000000000ff0000L ) >> 16 );
    mBlock[ 118 ] = (uint8_t) ( ( mBitCount[ 0 ] & 0x000000000000ff00L ) >> 8 );
    mBlock[ 119 ] = (uint8_t)  ( mBitCount[ 0 ] & 0x00000000000000ffL );
    mBlock[ 120 ] = (uint8_t) ( ( mBitCount[ 1 ] & 0xff00000000000000L ) >> 56 );
    mBlock[ 121 ] = (uint8_t) ( ( mBitCount[ 1 ] & 0x00ff000000000000L ) >> 48 );
    mBlock[ 122 ] = (uint8_t) ( ( mBitCount[ 1 ] & 0x0000ff0000000000L ) >> 40 );
    mBlock[ 123 ] = (uint8_t) ( ( mBitCount[ 1 ] & 0x000000ff00000000L ) >> 32 );
    mBlock[ 124 ] = (uint8_t) ( ( mBitCount[ 1 ] & 0x00000000ff000000L ) >> 24 );
    mBlock[ 125 ] = (uint8_t) ( ( mBitCount[ 1 ] & 0x0000000000ff0000L ) >> 16 );
    mBlock[ 126 ] = (uint8_t) ( ( mBitCount[ 1 ] & 0x000000000000ff00L ) >> 8 );
    mBlock[ 127 ] = (uint8_t)  ( mBitCount[ 1 ] & 0x00000000000000ffL );

    // Transform the last message block
    transform( );
}

/**
 * @copydoc HashingBase::finalize()
 */
void SHA2_512::finalize( ) {
    int32_t i;

    // Pad the last message block
    pad( );

    // Copy the digest number in the resulting buffer. The resulting
    // digest is big-endian.
    for( i = 0; i < 8; i++ ) {
        mHash[ ( i * 8 ) ] = (uint8_t) ( ( mState[ i ] & 0xff00000000000000L ) >> 56 );
        mHash[ ( i * 8 ) + 1 ] = (uint8_t) ( ( mState[ i ] & 0x00ff000000000000L ) >> 48 );
        mHash[ ( i * 8 ) + 2 ] = (uint8_t) ( ( mState[ i ] & 0x0000ff0000000000L ) >> 40 );
        mHash[ ( i * 8 ) + 3 ] = (uint8_t) ( ( mState[ i ] & 0x000000ff00000000L ) >> 32 );
        mHash[ ( i * 8 ) + 4 ] = (uint8_t) ( ( mState[ i ] & 0x00000000ff000000L ) >> 24 );
        mHash[ ( i * 8 ) + 5 ] = (uint8_t) ( ( mState[ i ] & 0x0000000000ff0000L ) >> 16 );
        mHash[ ( i * 8 ) + 6 ] = (uint8_t) ( ( mState[ i ] & 0x000000000000ff00L ) >> 8 );
        mHash[ ( i * 8 ) + 7 ] = (uint8_t)  ( mState[ i ] & 0x00000000000000ffL );
    }

    // Clear sensitive information
    clear( );
}

/**
 * Clears internal data after finalization.
 */
void SHA2_512::clear( ) {
    ::memset( mBlock, 0, sizeof ( mBlock ) );
    ::memset( mBitCount, 0, sizeof ( mBitCount ) );
    ::memset( mState, 0, sizeof ( mState ) );
    mIndex = 0;
}

/**
 * Transformation rounds.
 */
void SHA2_512::transform( ) {
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
                ( (uint64_t) mBlock[ i * 8 + 7 ] );
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

void* hash_sha2_512_create( ) {
    return new SHA2_512( );
}

int hash_sha2_512_init( void *h ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->init( );
    }

    return rc;
}

int hash_sha2_512_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->update( buf, len );
    }

    return rc;
}

int hash_sha2_512_finalize( void *h ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->finalize( );
    }

    return rc;
}

int hash_sha2_512_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = sha->getValue( buf, len );
    }

    return rc;
}

int hash_sha2_512_destroy( void *h ) {
    int rc = 0;
    SHA2_512 *sha = dynamic_cast<SHA2_512 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        delete sha;
    }

    return rc;
}

// EOF: sha2.cpp

