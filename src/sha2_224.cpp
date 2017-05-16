// ////////////////////////////////////////////////////////////////////////////
// System:     libHash
// File:       sha2_224.cpp
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-24
//
// Description
// Implementation of SHA-2 224-bits hashing algorithm.
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

void SHA2_224::init() {
    // Initial context state
    mState[ 0 ] = 0xc1059ed8;
    mState[ 1 ] = 0x367cd507;
    mState[ 2 ] = 0x3070dd17;
    mState[ 3 ] = 0xf70e5939;
    mState[ 4 ] = 0xffc00b31;
    mState[ 5 ] = 0x68581511;
    mState[ 6 ] = 0x64f98fa7;
    mState[ 7 ] = 0xbefa4fa4;
}

/* ------------------------------------------------------------------------- */

void SHA2_224::finalize() {
    int32_t i;

    // Finalization is the same as SHA2-256
    SHA2_256::finalize();

    // Copy the digest number in the resulting buffer. The resulting
    // hash is big-endian
    for( i = 0; i < 6; i++ ) {
        mHash[ ( i * 4 ) ] = (uint8_t) (( mState[ i ] & 0xff000000 ) >> 24 );
        mHash[ ( i * 4 ) + 1 ] = (uint8_t) (( mState[ i ] & 0x00ff0000 ) >> 16 );
        mHash[ ( i * 4 ) + 2 ] = (uint8_t) (( mState[ i ] & 0x0000ff00 ) >> 8 );
        mHash[ ( i * 4 ) + 3 ] = (uint8_t)  ( mState[ i ] & 0x000000ff );
    }

    // Clear sensitive information
    clear();
}

// -------------------------------------------------------------------------

void* hash_sha2_224_create() {
    return new SHA2_256();
}

// -------------------------------------------------------------------------

int hash_sha2_224_init( void *h ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->init();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_224_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->update( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_224_finalize( void *h ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        sha->finalize();
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_224_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = sha->getValue( buf, len );
    }

    return rc;
}

// -------------------------------------------------------------------------

int hash_sha2_224_destroy( void *h ) {
    int rc = 0;
    SHA2_224 *sha = dynamic_cast<SHA2_224 *> ( (HashingBase *) h );

    if(  sha != NULL ) {
        rc = 1;
        delete sha;
    }

    return rc;
}

// EOF: sha2_224.cpp

