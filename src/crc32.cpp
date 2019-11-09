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

/**
 * Lookup table for the corresponding reflective bits for the byte value.
 */
const uint8_t reflectedBytes[] = {
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x11, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
};

bool CRC32::msTableInit = false;
uint32_t CRC32::msLookup[ 256 ];
bool CRC32C::msTableInit = false;
uint32_t CRC32C::msLookup[ 256 ];

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

uint32_t reflective32( uint32_t value );

//-----------------------------------------------------------------------------
// IMPLEMENTATION
//-----------------------------------------------------------------------------

/**
 * @brief Returns the reflective 32-bits value of the specified value.
 *
 * A reflective value is a value where each bit are swapped. For example, the reflective
 * value of 0x55 (0b01010101) is 0xAA (0b10101010), 0x87 (0b10000111) is 0xE1 (0b11100001),
 * etc.
 *
 * @param value Initial 32-bits value.
 *
 * @return the reflective value.
 */
uint32_t reflective32( uint32_t value ) {
    uint32_t tmp = 0;
    uint32_t loBit;
    uint32_t hiBit;
    for( int i = 0; i < 16; i++ ) {
        loBit = value & ( 1 << i );
        hiBit = value & ( 1 << ( 31 - i ) );
        tmp |= ( loBit << ( 31 - ( i * 2 ) ) );
        tmp |= ( hiBit >> ( 31 - ( i * 2 ) ) );
    }

    return tmp;
}

//=== CRC32Base implementation ================================================

CRC32Base::CRC32Base( uint32_t initValue, uint32_t polynomial ) : HashingBase( 32 ) {
    mInit = initValue;
    mPolynomial = polynomial;
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

    for( uint32_t n = 0; n < 256; n++ ) {
        remainder = n;

        for( int i = 0 ; i < 8 ; i++ ) {
            if ( remainder & 1 ) {
                remainder = ( remainder >> 1 ) ^ mPolynomial;
            }
            else {

                remainder >>= 1;
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

    while( size-- ) {

        mState = lookupTable[ ( mState  ^ *buffer ) & 0xff ] ^ ( mState >> 8 );
        buffer++;
    }
}

/**
 * @copydoc HashingBase::finalize()
 */
void CRC32Base::finalize( ) {

    mHash[ 0 ] = (uint8_t) ( ( mState & 0xff000000 ) >> 24 );
    mHash[ 1 ] = (uint8_t) ( ( mState & 0x00ff0000 ) >> 16 );
    mHash[ 2 ] = (uint8_t) ( ( mState & 0x0000ff00 ) >> 8 );
    mHash[ 3 ] = (uint8_t) ( mState & 0x000000ff );

    mState = 0;
}

//=== CRC32 implementation ====================================================

/**
 * @brief Constructor
 *
 * Initializes the CRC with the polynomial 0x04c11db7.
 */
CRC32::CRC32( ) : CRC32Base( 0xffffffff, reflective32( 0x04c11db7 ) ) {
    if( ! CRC32::msTableInit ) {
        // Initialize the lookup
        initLookupTable( CRC32::msLookup );
        CRC32::msTableInit = true;
    }
}

CRC32::~CRC32( ) { }

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void CRC32::update( const void *data, size_t size ) {
    CRC32Base::update( CRC32::msLookup, data, size );
}

void CRC32::finalize( ) {
    mState = ~mState;  // Same as mState ^ 0xffffffff;
    CRC32Base::finalize( );
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
CRC32C::CRC32C( ) : CRC32Base( 0xffffffff, reflective32( 0x1edc6f41 ) ) {
    if( ! CRC32C::msTableInit ) {
        // Initialize the lookup table.
        initLookupTable( CRC32C::msLookup  );
        CRC32C::msTableInit = true;
    }
}

CRC32C::~CRC32C( ) { }

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void CRC32C::update( const void *data, size_t size ) {
    CRC32Base::update( CRC32C::msLookup, data, size );
}

void CRC32C::finalize( ) {
    mState = ~mState;  // Same as mState ^ 0xffffffff;
    CRC32Base::finalize( );
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
// EOF: crc32.cpp
