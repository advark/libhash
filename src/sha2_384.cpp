// ////////////////////////////////////////////////////////////////////////////
// System:     libHash
// File:       sha2_384.cpp
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-24
//
// Description
// Implementation of SHA-2 384-bits hashing algorithm.
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
//
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

/* ------------------------------------------------------------------------- */

void SHA2_384::init() {
    // Initial context state
    mState[ 0 ] = 0xcbbb9d5dc1059ed8L;
    mState[ 1 ] = 0x629a292a367cd507L;
    mState[ 2 ] = 0x9159015a3070dd17L;
    mState[ 3 ] = 0x152fecd8f70e5939L;
    mState[ 4 ] = 0x67332667ffc00b31L;
    mState[ 5 ] = 0x8eb44a8768581511L;
    mState[ 6 ] = 0xdb0c2e0d64f98fa7L;
    mState[ 7 ] = 0x47b5481dbefa4fa4L;
}

/* ------------------------------------------------------------------------- */

void SHA2_384::finalize() {
    int32_t i;

    SHA2_512::finalize();

    // Copy the digest number in the resulting buffer. The resulting
    // digest is big-endian.
    for( i = 0; i < 6; i++ ) {
        mHash[ ( i * 8 ) ] = (uint8_t) (( mState[ i ] & 0xff00000000000000L ) >> 56 );
        mHash[ ( i * 8 ) + 1 ] = (uint8_t) (( mState[ i ] & 0x00ff000000000000L ) >> 48 );
        mHash[ ( i * 8 ) + 2 ] = (uint8_t) (( mState[ i ] & 0x0000ff0000000000L ) >> 40 );
        mHash[ ( i * 8 ) + 3 ] = (uint8_t) (( mState[ i ] & 0x000000ff00000000L ) >> 32 );
        mHash[ ( i * 8 ) + 4 ] = (uint8_t) (( mState[ i ] & 0x00000000ff000000L ) >> 24 );
        mHash[ ( i * 8 ) + 5 ] = (uint8_t) (( mState[ i ] & 0x0000000000ff0000L ) >> 16 );
        mHash[ ( i * 8 ) + 6 ] = (uint8_t) (( mState[ i ] & 0x000000000000ff00L ) >> 8 );
        mHash[ ( i * 8 ) + 7 ] = (uint8_t) (( mState[ i ] & 0x00000000000000ffL ));
    }

    // Clear sensitive information
    clear();
}

// -------------------------------------------------------------------------

void* hash_sha2_384_create() {
    return new SHA2_384();
}

// -------------------------------------------------------------------------

int hash_sha2_384_init( void *h ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->init();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_384_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->update( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_384_finalize( void *h ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->finalize();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_384_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = sha->getValue( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_384_destroy( void *h ) {
    int rc = 0;
    SHA2_384 *sha = dynamic_cast<SHA2_384 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        delete sha;
    }

    return rc;
}

// EOF: sha2_384.cpp

