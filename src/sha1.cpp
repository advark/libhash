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

//=============================================================================
// System:     libHash
// File:       sha1.cpp
//
// Author:     Yanick Poirier
// Date:       2017-01-21
//
// Description
// Implementation of SHA-1 family algorithms
//=============================================================================

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>
#include "../include/libhash/defs.h"
#include "../include/libhash/hashbase.h"
#include "../include/libhash/sha1.h"

using namespace libhash;

//-----------------------------------------------------------------------------
// CONSTANTS & MACROS
//-----------------------------------------------------------------------------

// SHA-1 constants
uint32_t KSha1[]   = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

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

inline uint32_t CH( uint32_t x, uint32_t y, uint32_t z ) {
    return ( x & y ) ^ ( ~x & z );
}

inline uint32_t PARITY( uint32_t x, uint32_t y, uint32_t z ) {
    return x ^ y ^ z;
}

inline uint32_t MAJ( uint32_t x, uint32_t y, uint32_t z ) {
    return ( x & y ) ^ ( x & z ) ^ ( y & z );
}

//=== SHA-1 implementation ====================================================

/**
 * @copydoc HashingBase::init()
 */
void SHA1::init( ) {
    // Initial state values
    mState[ 0 ] = 0x67452301;
    mState[ 1 ] = 0xefcdab89;
    mState[ 2 ] = 0x98badcfe;
    mState[ 3 ] = 0x10325476;
    mState[ 4 ] = 0xc3d2e1f0;

    mBitCount = 0;
    mIndex = 0;
}

/**
 * @copydoc HashingBase::update( const void *, lhUInt32 )
 */
void SHA1::update( const void *data, size_t size ) {
    uint32_t i;

    // Update number of bits
    mBitCount += size << 3;

    for( i = 0; i < size; i++ ) {
        mBlock[ mIndex++ ] = ( (uint8_t *) data )[ i ];
        if( mIndex == 64 ) {
            transform( );
            mIndex = 0;
        }
    }
}

/**
 * @copydoc HashingBase::finalize()
 */
void SHA1::finalize( ) {
    if( mIndex > 55 ) {
        if( mIndex < 64 ) {
            // Not enough room to hold the padding bit and mesage length. So we pad the
            // block, process it and continue padding on a second block.
            mBlock[ mIndex ] = (uint8_t) 0x80;
            mIndex++;
            ::memset( mBlock + mIndex, 0, 64 - mIndex );

            transform( );

            // Pad only 56 bytes on the second block. The last 8 will be filled later with
            // the message length.
            ::memset( mBlock, 0, 56 );
        }
        else {
            transform( );

            mBlock[ 0 ] = 0x80;
            ::memset( mBlock + 1, 0, 55 );
        }
    }
    else {
        // There is enough room for the padding bits and the message length
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
    mBlock[ 63 ] = (uint8_t) ( mBitCount & 0x00000000000000FF );

    // Transform the last message block
    transform( );

    // Copy the digest number in the resulting buffer. The resulting digest is big-endian
    for( int i = 0; i < 5; i++ ) {
        mHash[ ( i * 4 ) ] = (uint8_t) ( ( mState[ i ] & 0xFF000000 ) >> 24 );
        mHash[ ( i * 4 ) + 1 ] = (uint8_t) ( ( mState[ i ] & 0x00FF0000 ) >> 16 );
        mHash[ ( i * 4 ) + 2 ] = (uint8_t) ( ( mState[ i ] & 0x0000FF00 ) >> 8 );
        mHash[ ( i * 4 ) + 3 ] = (uint8_t)  ( mState[ i ] & 0x000000FF );
    }

    // Clear sensitive information
    ::memset( mState, 0, sizeof (mState ) );
    ::memset( mBlock, 0, sizeof (mBlock ) );
    mIndex = 0;
    mBitCount = 0;
}

/**
 * Executes the SHA-1 transformation rounds.
 */
void SHA1::transform( ) {
    uint32_t tmp;
    uint32_t W[80];
    uint32_t a, b, c, d, e;  // Working variables
    int32_t  t;

    // Prepare the buffer schedule
    for( t = 0; t < 16; t++ ) {
        W[ t ] = ( mBlock[ t * 4 ] << 24 ) |
                ( mBlock[ ( t * 4 ) + 1 ] << 16 ) |
                ( mBlock[ ( t * 4 ) + 2 ] << 8 ) |
                mBlock[ ( t * 4 ) + 3 ];
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

/**
 * Creates a new SHA-1 handler.
 *
 * @return pointer to the newly created SHA-1 handler or <tt>null</tt> on error.
 */
void* hash_sha1_create( ) {
    return new SHA1( );
}

/**
 * @brief Initializes the specified SHA-1 handler.
 *
 * This function prepares the SHA-1 handler for hashing data. It must be called prior the
 * first {@link hash_sha1_update} or {@link hash_sha1_final} calls.
 *
 * @param h Pointer to a valid SHA-1 handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not valid.
 */
int hash_sha1_init( void *h ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = 1;
        sha1->init( );
    }

    return rc;
}

/**
 * @brief Updates the specified SHA-1 handler's state with the data.
 *
 * This function updates the SHA-1 handler's state by hashing data. It must be called
 * after {@link hash_sha1_init} and before {@link hash_sha1_final}. The result of calling
 * this function before {@link hash_sha1_init} or after {@link hash_sha1_final} is
 * undefined.
 *
 * @param h   Pointer to a valid SHA-1 handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not valid.
 */
int hash_sha1_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = 1;
        sha1->update( buf, len );
    }

    return rc;
}

/**
 * @brief Finalizes the specified SHA-1 handler's state.
 *
 * This function finalizes the SHA-1 handler's state and returns the hashing value. It
 * must be called after {@link hash_sha1_init} The result of calling this function before
 * {@link hash_sha1_init} is undefined.
 *
 * @param h   Pointer to a valid SHA-1 handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not valid.
 */
int hash_sha1_finalize( void *h ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = 1;
        sha1->finalize( );
    }

    return rc;
}

/**
 * @brief Retrieves the hashing value after the last <tt>hash_sha1_finalize</tt> function
 * call.
 *
 * The result of calling this method prior to the {@link hash_sha1_finalize} method is
 * undefined. If the memory buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int hash_sha1_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA1 *sha1 = dynamic_cast<SHA1 *> ( (HashingBase *) h );

    if(  sha1 != NULL ) {
        rc = sha1->getValue( buf, len );
    }

    return rc;
}

/**
 * Destroys an existing SHA-1 handler.
 *
 * @param h Pointer to a valid SHA-1 handler. Cannot be <tt>NULL</tt>.
 * @return pointer to the newly created SHA-1 handler or <tt>null</tt> on error.
 */
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

