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
// File:       crc32.cpp
//
// Author:     Yanick Poirier
// Date:       2017-03-20
//
// Description
// CRC-32 hashing algorithm implementation.
//=============================================================================

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../include/libhash/defs.h"
#include "../include/libhash/hashbase.h"
#include "../include/libhash/crc32.h"

using namespace libhash;

//-----------------------------------------------------------------------------
// MACROS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// STRUCTURES & TYPEDEFS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CONSTANTS & STATIC VARIABLES
//-----------------------------------------------------------------------------

bool CRC32::msTableInit = false;
uint32_t CRC32::msLookup[ 256 ];

bool CRC32_BZip2::msTableInit = false;
uint32_t CRC32_BZip2::msLookup[ 256 ];

bool CRC32C::msTableInit = false;
uint32_t CRC32C::msLookup[ 256 ];

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// IMPLEMENTATION
//-----------------------------------------------------------------------------

//=== CRC32Base implementation ================================================

CRC32Base::CRC32Base( uint32_t initValue,
                      uint32_t polynomial,
                      uint32_t xorValue,
                      bool inReflect,
                      bool outReflect ) : CRCBase( 32, inReflect, outReflect ) {
    mInit = initValue;
    mPolynomial = polynomial;
    mXorValue = xorValue;
}

CRC32Base::~CRC32Base( ) { }

/**
 * @brief Initializes the lookup table.
 *
 * @param table     Array of the lookup entries to compute. The array must have room for
 *                  256 entries of 32-bits each.
 */
void CRC32Base::initLookupTable( uint32_t *table ) {
    uint32_t remainder;

    for( uint16_t n = 0; n < 256; n++ ) {
        remainder = n << 24;

        for( int i = 0 ; i < 8 ; i++ ) {
            if ( remainder & 0x80000000 ) {
                remainder = ( ( remainder << 1 ) ^ mPolynomial );
            }
            else {

                remainder = ( remainder << 1 );
            }
        }

        table[ n ] = remainder;
    }
}

/**
 * @copydoc HashingBase::init()
 */
void CRC32Base::init( ) {
    mState = mInit;
}

/**
 * @brief Update the CRC32 state.
 *
 * @param lookupTable   Lookup table to use
 * @param data          Data buffer use to update the current CRC.
 * @param size          Number of bytes in <tt>data</tt>
 */
void CRC32Base::update( uint32_t *lookupTable, const void *data, size_t size ) {
    uint8_t *buffer = (uint8_t *) data;
    uint8_t b;

    while( size-- ) {
        if( isInputReflected( ) ) {
            b = reflect( ( uint8_t ) * buffer );
        }
        else {
            b = *buffer;
        }

        mState = lookupTable[ ( ( mState >> 24 )  ^ b ) & 0xff ] ^ ( mState << 8 );
        buffer++;
    }
}

/**
 * @copydoc HashingBase::finalize()
 */
void CRC32Base::finalize( ) {
    mState = mState ^getXorValue( );

    if( isOutputReflected( ) ) {
        mHash[ 0 ] = reflect( (uint8_t) ( mState & 0x000000ff ) );
        mHash[ 1 ] = reflect( (uint8_t) ( ( mState & 0x0000ff00 ) >> 8 ) );
        mHash[ 2 ] = reflect( (uint8_t) ( ( mState & 0x00ff0000 ) >> 16 ) );
        mHash[ 3 ] = reflect( (uint8_t) ( ( mState & 0xff000000 ) >> 24 ) );
    }
    else {
        mHash[ 0 ] = (uint8_t) ( ( mState & 0xff000000 ) >> 24 );
        mHash[ 1 ] = (uint8_t) ( ( mState & 0x00ff0000 ) >> 16 );
        mHash[ 2 ] = (uint8_t) ( ( mState & 0x0000ff00 ) >> 8 );
        mHash[ 3 ] = (uint8_t) ( mState & 0x000000ff );
    }

    mState = 0;
}

//=== CRC32 implementation ====================================================

/**
 * @brief Constructor
 *
 * Initializes the CRC with the polynomial 0x04c11db7.
 */
CRC32::CRC32( ) : CRC32Base( 0xffffffff, 0x04c11db7, 0xffffffff, true, true ) {
    if( ! CRC32::msTableInit ) {
        // Initialize the lookup
        initLookupTable( CRC32::msLookup );
        CRC32::msTableInit = true;
    }
}

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void CRC32::update( const void *data, size_t size ) {
    CRC32Base::update( CRC32::msLookup, data, size );
}

/**
 * Creates a new CRC-32 handler.
 *
 * @return pointer to the newly created CRC-32 handler or <tt>null</tt> on error.
 */
void* hash_crc32_create( ) {

    return new CRC32( );
}

/**
 * @brief Initializes the specified CRC-32 handler.
 *
 * This function prepares the CRC-32 handler for hashing data. It must be called prior the
 * first {@link hash_crc32_update} or {@link hash_crc32_final} calls.
 *
 * @param h Pointer to a valid CRC-32 handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32_init( void *h ) {
    int rc = 0;
    CRC32 *crc = dynamic_cast<CRC32 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        crc->init( );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Updates the specified CRC-32 handler's state with the data.
 *
 * This function updates the CRC-32 handler's state by hashing data. It must be called
 * after {@link hash_crc32_init} and before {@link hash_crc32_final}. The result of
 * calling this function before {@link hash_crc32_init} or after {@link hash_crc32_final}
 * is undefined.
 *
 * @param h   Pointer to a valid CRC-32 handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    CRC32 *crc = dynamic_cast<CRC32 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        crc->update( buf, len );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Finalizes the specified CRC-32 handler's state.
 *
 * This function finalizes the CRC-32 handler's state and returns the hashing value. It
 * must be called after {@link hash_crc32_init} The result of calling this function before
 * {@link hash_crc32_init} is undefined.
 *
 * @param h   Pointer to a valid CRC-32 handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32_finalize( void *h ) {
    int rc = 0;
    CRC32 *crc = dynamic_cast<CRC32 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = 1;
        crc->finalize( );
    }

    return rc;
}

/**
 * @brief Retrieves the hashing value after the last  <tt>hash_crc32_finalize</tt>
 * function call.
 *
 * The result of calling this method prior to the {@link hash_crc32_finalize} method is
 * undefined. If the memory buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * If <tt>h</tt> is not a valid CRC-32 handler, the function returns immediately.
 *
 * @param h    Pointer to a valid CRC-32 handler.
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int hash_crc32_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    CRC32 *crc = dynamic_cast<CRC32 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = crc->getValue( buf, len );
    }

    return rc;
}

/**
 * Destroys an existing CRC-32 handler.
 *
 * @param h Pointer to a valid CRC-32 handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 on error.
 */
int hash_crc32_destroy( void *h ) {
    int rc = 0;
    CRC32 *crc = dynamic_cast<CRC32 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = 1;
        delete crc;
    }

    return rc;
}

//=== CRC32C implementation ===================================================

/**
 * @brief Constructor
 *
 * Initializes the CRC with the polynomial 0x1edc6f41.
 */
CRC32C::CRC32C( ) : CRC32Base( 0xffffffff, 0x1edc6f41, 0xffffffff, true, true ) {
    if( ! CRC32C::msTableInit ) {
        // Initialize the lookup table.
        initLookupTable( CRC32C::msLookup  );
        CRC32C::msTableInit = true;
    }
}

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void CRC32C::update( const void *data, size_t size ) {
    CRC32Base::update( CRC32C::msLookup, data, size );
}

/**
 * Creates a new CRC-32C handler.
 *
 * @return pointer to the newly created CRC-32C handler or <tt>null</tt> on error.
 */
void* hash_crc32c_create( ) {

    return new CRC32C( );
}

/**
 * @brief Initializes the specified CRC-32C handler.
 *
 * This function prepares the CRC-32C handler for hashing data. It must be called prior the
 * first {@link hash_crc32c_update} or {@link hash_crc32c_final} calls.
 *
 * @param h Pointer to a valid CRC-32C handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32c_init( void *h ) {
    int rc = 0;
    CRC32C *crc = dynamic_cast<CRC32C *> ( (CRC32Base *) h );

    if(  crc != NULL ) {

        crc->init( );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Updates the specified CRC-32C handler's state with the data.
 *
 * This function updates the CRC-32C handler's state by hashing data. It must be called
 * after {@link hash_crc32c_init} and before {@link hash_crc32c_final}. The result of
 * calling this function before {@link hash_crc32c_init} or after {@link hash_crc32c_final}
 * is undefined.
 *
 * @param h   Pointer to a valid CRC-32C handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32c_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    CRC32C *crc = dynamic_cast<CRC32C *> ( (CRC32Base *) h );

    if(  crc != NULL ) {

        crc->update( buf, len );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Finalizes the specified CRC-32C handler's state.
 *
 * This function finalizes the CRC-32C handler's state and returns the hashing value. It
 * must be called after {@link hash_crc32c_init} The result of calling this function before
 * {@link hash_crc32c_init} is undefined.
 *
 * @param h   Pointer to a valid CRC-32C handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32c_finalize( void *h ) {
    int rc = 0;
    CRC32C *crc = dynamic_cast<CRC32C *> ( (CRC32Base *) h );

    if(  crc != NULL ) {

        rc = 1;
        crc->finalize( );
    }

    return rc;
}

/**
 * @brief Retrieves the hashing value after the last  <tt>hash_crc32c_finalize</tt>
 * function call.
 *
 * The result of calling this method prior to the {@link hash_crc32c_finalize} method is
 * undefined. If the memory buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * If <tt>h</tt> is not a valid CRC-32C handler, the function returns immediately.
 *
 * @param h    Pointer to a valid CRC-32C handler.
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int hash_crc32c_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    CRC32C *crc = dynamic_cast<CRC32C *> ( (CRC32Base *) h );

    if(  crc != NULL ) {

        rc = crc->getValue( buf, len );
    }

    return rc;
}

/**
 * Destroys an existing CRC-32C handler.
 *
 * @param h Pointer to a valid CRC-32C handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 on error.
 */
int hash_crc32c_destroy( void *h ) {
    int rc = 0;
    CRC32C *crc = dynamic_cast<CRC32C *> ( (CRC32Base *) h );

    if(  crc != NULL ) {
        rc = 1;
        delete crc;
    }

    return rc;
}

//=== CRC32_BZip2 implementation ==============================================

/**
 * @brief Constructor
 *
 * Initializes the CRC with the polynomial 0x1edc6f41.
 */
CRC32_BZip2::CRC32_BZip2( ) : CRC32Base( 0xffffffff, 0x04c11db7, 0xffffffff, false, false ) {
    if( ! CRC32_BZip2::msTableInit ) {
        // Initialize the lookup table.
        initLookupTable( CRC32_BZip2::msLookup  );
        CRC32_BZip2::msTableInit = true;
    }
}

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void CRC32_BZip2::update( const void *data, size_t size ) {
    CRC32Base::update( CRC32_BZip2::msLookup, data, size );
}

/**
 * Creates a new CRC-32C handler.
 *
 * @return pointer to the newly created CRC-32C handler or <tt>null</tt> on error.
 */
void* hash_crc32bzip2_create( ) {

    return new CRC32_BZip2( );
}

/**
 * @brief Initializes the specified CRC-32C handler.
 *
 * This function prepares the CRC-32C handler for hashing data. It must be called prior the
 * first {@link hash_crc32bzip2_update} or {@link hash_crc32bzip2_final} calls.
 *
 * @param h Pointer to a valid CRC-32C handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32bzip2_init( void *h ) {
    int rc = 0;
    CRC32_BZip2 *crc = dynamic_cast<CRC32_BZip2 *> ( (CRC32Base *) h );

    if(  crc != NULL ) {

        crc->init( );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Updates the specified CRC-32C handler's state with the data.
 *
 * This function updates the CRC-32C handler's state by hashing data. It must be called
 * after {@link hash_crc32bzip2_init} and before {@link hash_crc32bzip2_final}. The result of
 * calling this function before {@link hash_crc32bzip2_init} or after {@link hash_crc32bzip2_final}
 * is undefined.
 *
 * @param h   Pointer to a valid CRC-32C handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32bzip2_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    CRC32_BZip2 *crc = dynamic_cast<CRC32_BZip2 *> ( (CRC32Base *) h );

    if(  crc != NULL ) {

        crc->update( buf, len );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Finalizes the specified CRC-32C handler's state.
 *
 * This function finalizes the CRC-32C handler's state and returns the hashing value. It
 * must be called after {@link hash_crc32bzip2_init} The result of calling this function before
 * {@link hash_crc32bzip2_init} is undefined.
 *
 * @param h   Pointer to a valid CRC-32C handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc32bzip2_finalize( void *h ) {
    int rc = 0;
    CRC32_BZip2 *crc = dynamic_cast<CRC32_BZip2 *> ( (CRC32Base *) h );

    if(  crc != NULL ) {

        rc = 1;
        crc->finalize( );
    }

    return rc;
}

/**
 * @brief Retrieves the hashing value after the last  <tt>hash_crc32bzip2_finalize</tt>
 * function call.
 *
 * The result of calling this method prior to the {@link hash_crc32bzip2_finalize} method is
 * undefined. If the memory buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * If <tt>h</tt> is not a valid CRC-32C handler, the function returns immediately.
 *
 * @param h    Pointer to a valid CRC-32C handler.
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int hash_crc32bzip2_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    CRC32_BZip2 *crc = dynamic_cast<CRC32_BZip2 *> ( (CRC32Base *) h );

    if(  crc != NULL ) {

        rc = crc->getValue( buf, len );
    }

    return rc;
}

/**
 * Destroys an existing CRC-32C handler.
 *
 * @param h Pointer to a valid CRC-32C handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 on error.
 */
int hash_crc32bzip2_destroy( void *h ) {
    int rc = 0;
    CRC32_BZip2 *crc = dynamic_cast<CRC32_BZip2 *> ( (CRC32Base *) h );

    if(  crc != NULL ) {
        rc = 1;
        delete crc;
    }

    return rc;
}
// EOF: crc32.cpp
