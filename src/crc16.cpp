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
// File:       crc16.cpp
//
// Author:     Yanick Poirier
// Date:       2019-11-09
//
// Description
// CRC-16 hashing algorithm implementation.
//=============================================================================

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../include/libhash/defs.h"
#include "../include/libhash/hashbase.h"
#include "../include/libhash/crc16.h"

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

bool CRC16_CCITT::msTableInit = false;
uint16_t CRC16_CCITT::msLookup[ 256 ];

bool CRC16_XModem::msTableInit = false;
uint16_t CRC16_XModem::msLookup[ 256 ];

bool CRC16_X25::msTableInit = false;
uint16_t CRC16_X25::msLookup[ 256 ];

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// IMPLEMENTATION
//-----------------------------------------------------------------------------

//=== CRC16Base implementation ================================================

/**
 * @brief CRC-16 base constructor.
 *
 * @param initValue     CRC initial value.
 * @param polynomial    CRC polynomial.
 * @param xorValue      Value to be XOR at the end of the CRC calculation.
 * @param inReflect     Input reflection flag. If <tt>true</tt>, the input data is
 *                      reflected before use.
 * @param outReflect    Output reflection flag. If <tt>true</tt>, the output value is
 *                      reflected.
 */
CRC16Base::CRC16Base( uint16_t initValue,
                      uint16_t polynomial,
                      uint16_t xorValue,
                      bool inReflect,
                      bool outReflect ) : CRCBase( 16, inReflect, outReflect ) {
    mInit = initValue;
    mPolynomial = polynomial;
    mXorValue = xorValue;
    //    mInReflection = inReflect;
    //    mOutReflection = outReflect;
}

#include <stdio.h>

CRC16Base::~CRC16Base( ) { }

/**
 * @brief Initializes the lookup table.
 *
 * @param table     Array of the lookup entries to be calculated. The array must have room
 *                  for 256 entries of 16-bits each.
 */
void CRC16Base::initLookupTable( uint16_t *table ) {
    uint16_t remainder;

    for( uint16_t n = 0; n < 256; n++ ) {
        remainder = n << 8;

        for( int i = 0 ; i < 8 ; i++ ) {
            if ( remainder & 0x8000 ) {
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
void CRC16Base::init( ) {
    mState = mInit;
}

/**
 * @brief Update the CRC16 state.
 *
 * @param lookupTable   Lookup table to use
 * @param data          Data buffer use to update the current CRC.
 * @param size          Number of bytes in <tt>data</tt>
 */
void CRC16Base::update( uint16_t *lookupTable, const void *data, size_t size ) {
    uint8_t *buffer = (uint8_t *) data;
    uint8_t b;

    while( size-- ) {
        if( isInputReflected( ) ) {
            b = reflect( ( uint8_t ) * buffer );
        }
        else {
            b = *buffer;
        }

        mState = lookupTable[ ( ( mState >> 8 )  ^ b ) & 0xff ] ^ ( mState << 8 );
        buffer++;
    }
}

/**
 * @copydoc HashingBase::finalize()
 */
void CRC16Base::finalize( ) {
    mState = mState ^getXorValue( );

    if( isOutputReflected( ) ) {
        mHash[0] = reflect( (uint8_t) ( mState & 0x00ff ) );
        mHash[1] = reflect( (uint8_t) ( ( mState & 0xff00 ) >> 8 ) );
    }
    else {

        mHash[ 0 ] = (uint8_t) ( ( ( mState & 0xff00 ) >> 8 ) );
        mHash[ 1 ] = (uint8_t) ( mState & 0x00ff );
    }

    mState = 0;
}

//=== CRC16_CCITT implementation ==============================================

/**
 * @brief Constructor
 *
 * Initializes the CRC with the polynomial 0x1021.
 */
CRC16_CCITT::CRC16_CCITT( ) : CRC16Base( 0xffff, 0x1021, 0, false, false )  {
    if( ! CRC16_CCITT::msTableInit ) {
        // Initialize the lookup

        initLookupTable( CRC16_CCITT::msLookup );
        CRC16_CCITT::msTableInit = true;
    }
}

CRC16_CCITT::~CRC16_CCITT( ) { }

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void CRC16_CCITT::update( const void *data, size_t size ) {

    CRC16Base::update( CRC16_CCITT::msLookup, data, size );
}

//void CRC16_CCITT::finalize( ) {
//    mState = mState ^getXorValue( );
//    CRC16Base::finalize( );
//}

/**
 * Creates a new CRC-16-CCITT handler.
 *
 * @return pointer to the newly created CRC-16-CCITT handler or <tt>null</tt> on error.
 */
void* hash_crc16_ccitt_create( ) {

    return new CRC16_CCITT( );
}

/**
 * @brief Initializes the specified CRC-16-CCITT handler.
 *
 * This function prepares the CRC-16-CCITT handler for hashing data. It must be called prior the
 * first {@link hash_crc16_ccitt_update} or {@link hash_crc16_ccitt_final} calls.
 *
 * @param h Pointer to a valid CRC-16-CCITT handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_ccitt_init( void *h ) {
    int rc = 0;
    CRC16_CCITT *crc = dynamic_cast<CRC16_CCITT *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        crc->init( );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Updates the specified CRC-16-CCITT handler's state with the data.
 *
 * This function updates the CRC-16-CCITT handler's state by hashing data. It must be called
 * after {@link hash_crc16_ccitt_init} and before {@link hash_crc16_ccitt_final}. The result of
 * calling this function before {@link hash_crc16_ccitt_init} or after {@link hash_crc16_ccitt_final}
 * is undefined.
 *
 * @param h   Pointer to a valid CRC-16-CCITT handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_ccitt_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    CRC16_CCITT *crc = dynamic_cast<CRC16_CCITT *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        crc->update( buf, len );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Finalizes the specified CRC-16-CCITT handler's state.
 *
 * This function finalizes the CRC-16-CCITT handler's state and returns the hashing value. It
 * must be called after {@link hash_crc16_ccitt_init} The result of calling this function before
 * {@link hash_crc16_ccitt_init} is undefined.
 *
 * @param h   Pointer to a valid CRC-16-CCITT handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_ccitt_finalize( void *h ) {
    int rc = 0;
    CRC16_CCITT *crc = dynamic_cast<CRC16_CCITT *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = 1;
        crc->finalize( );
    }

    return rc;
}

/**
 * @brief Retrieves the hashing value after the last  <tt>hash_crc16_ccitt_finalize</tt>
 * function call.
 *
 * The result of calling this method prior to the {@link hash_crc16_ccitt_finalize} method is
 * undefined. If the memory buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * If <tt>h</tt> is not a valid CRC-16-CCITT handler, the function returns immediately.
 *
 * @param h    Pointer to a valid CRC-16-CCITT handler.
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int hash_crc16_ccitt_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    CRC16_CCITT *crc = dynamic_cast<CRC16_CCITT *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = crc->getValue( buf, len );
    }

    return rc;
}

/**
 * Destroys an existing CRC-16-CCITT handler.
 *
 * @param h Pointer to a valid CRC-16-CCITT handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 on error.
 */
int hash_crc16_ccitt_destroy( void *h ) {
    int rc = 0;
    CRC16_CCITT *crc = dynamic_cast<CRC16_CCITT *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = 1;
        delete crc;
    }

    return rc;
}

//=== CRC16_XMODEM implementation =============================================

/**
 * @brief Constructor
 *
 * Initializes the CRC with the polynomial 0x1021.
 */
CRC16_XModem::CRC16_XModem( ) : CRC16Base( 0, 0x1021, 0, false, false )  {
    if( ! CRC16_XModem::msTableInit ) {
        // Initialize the lookup
        initLookupTable( CRC16_XModem::msLookup );
        CRC16_XModem::msTableInit = true;
    }
}

CRC16_XModem::~CRC16_XModem( ) { }

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void CRC16_XModem::update( const void *data, size_t size ) {

    CRC16Base::update( CRC16_XModem::msLookup, data, size );
}

/**
 * Creates a new CRC-16-XMODEM handler.
 *
 * @return pointer to the newly created CRC-16-XMODEM handler or <tt>null</tt> on error.
 */
void* hash_crc16_xmodem_create( ) {

    return new CRC16_XModem( );
}

/**
 * @brief Initializes the specified CRC-16-XMODEM handler.
 *
 * This function prepares the CRC-16-XMODEM handler for hashing data. It must be called
 * prior the first {@link hash_crc16_xmodem_update} or {@link hash_crc16_xmodem_final}
 * calls.
 *
 * @param h Pointer to a valid CRC-16-XMODEM handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_xmodem_init( void *h ) {
    int rc = 0;
    CRC16_XModem *crc = dynamic_cast<CRC16_XModem *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        crc->init( );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Updates the specified CRC-16-XMODEM handler's state with the data.
 *
 * This function updates the CRC-16-XMODEM handler's state by hashing data. It must be
 * called after {@link hash_crc16_xmodem_init} and before {@link hash_crc16_xmodem_final}.
 * The result of calling this function before {@link hash_crc16_xmodem_init} or after
 * {@link hash_crc16_xmodem_final} is undefined.
 *
 * @param h   Pointer to a valid CRC-16-XMODEM handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_xmodem_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    CRC16_XModem *crc = dynamic_cast<CRC16_XModem *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        crc->update( buf, len );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Finalizes the specified CRC-16-XMODEM handler's state.
 *
 * This function finalizes the CRC-16-XMODEM handler's state and returns the hashing value.
 * It must be called after {@link hash_crc16_xmodem_init} The result of calling this
 * function before {@link hash_crc16_xmodem_init} is undefined.
 *
 * @param h   Pointer to a valid CRC-16-XMODEM handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_xmodem_finalize( void *h ) {
    int rc = 0;
    CRC16_XModem *crc = dynamic_cast<CRC16_XModem *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = 1;
        crc->finalize( );
    }

    return rc;
}

/**
 * @brief Retrieves the hashing value after the last  <tt>hash_crc16_xmodem_finalize</tt>
 * function call.
 *
 * The result of calling this method prior to the {@link hash_crc16_xmodem_finalize}
 * method is undefined. If the memory buffer is smaller than the hash size, only the
 * higher part of the hash value is returned.
 *
 * If <tt>h</tt> is not a valid CRC-16-XMODEM handler, the function returns immediately.
 *
 * @param h    Pointer to a valid CRC-16-XMODEM handler.
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int hash_crc16_xmodem_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    CRC16_XModem *crc = dynamic_cast<CRC16_XModem *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = crc->getValue( buf, len );
    }

    return rc;
}

/**
 * Destroys an existing CRC-16-XMODEM handler.
 *
 * @param h Pointer to a valid CRC-16-XMODEM handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 on error.
 */
int hash_crc16_xmodem_destroy( void *h ) {
    int rc = 0;
    CRC16_XModem *crc = dynamic_cast<CRC16_XModem *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = 1;
        delete crc;
    }

    return rc;
}

//=== CRC16_X25 implementation ================================================

/**
 * @brief Constructor
 *
 * Initializes the CRC with the polynomial 0x1021.
 */
CRC16_X25::CRC16_X25( ) : CRC16Base( 0xffff, 0x1021, 0xffff, true, true ) {
    if( ! CRC16_X25::msTableInit ) {
        // Initialize the lookup table.

        initLookupTable( CRC16_X25::msLookup  );
        CRC16_X25::msTableInit = true;
    }
}

CRC16_X25::~CRC16_X25( ) { }

/**
 * @copydoc HashingBase::update( const void *, size_t )
 */
void CRC16_X25::update( const void *data, size_t size ) {

    CRC16Base::update( CRC16_X25::msLookup, data, size );
}

//void CRC16_X25::finalize( ) {
//    mState = mState ^ getXorValue( );
//    CRC16Base::finalize( );
//}

/**
 * Creates a new CRC-16-X25 handler.
 *
 * @return pointer to the newly created CRC-16-X25 handler or <tt>null</tt> on error.
 */
void* hash_crc16_x25_create( ) {

    return new CRC16_X25( );
}

/**
 * @brief Initializes the specified CRC-16-X25 handler.
 *
 * This function prepares the CRC-16-X25 handler for hashing data. It must be called prior the
 * first {@link hash_crc16_x25_update} or {@link hash_crc16_x25_final} calls.
 *
 * @param h Pointer to a valid CRC-16-X25 handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_x25_init( void *h ) {
    int rc = 0;
    CRC16_X25 *crc = dynamic_cast<CRC16_X25 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        crc->init( );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Updates the specified CRC-16-X25 handler's state with the data.
 *
 * This function updates the CRC-16-X25 handler's state by hashing data. It must be called
 * after {@link hash_crc16_x25_init} and before {@link hash_crc16_x25_final}. The result of
 * calling this function before {@link hash_crc16_x25_init} or after {@link hash_crc16_x25_final}
 * is undefined.
 *
 * @param h   Pointer to a valid CRC-16-X25 handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_x25_update( void *h, void *buf, size_t len ) {
    int rc = 0;
    CRC16_X25 *crc = dynamic_cast<CRC16_X25 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        crc->update( buf, len );
        rc = 1;
    }

    return rc;
}

/**
 * @brief Finalizes the specified CRC-16-X25 handler's state.
 *
 * This function finalizes the CRC-16-X25 handler's state and returns the hashing value. It
 * must be called after {@link hash_crc16_x25_init} The result of calling this function before
 * {@link hash_crc16_x25_init} is undefined.
 *
 * @param h   Pointer to a valid CRC-16-X25 handler. Cannot be <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success or 0 if <tt>h</tt> is not valid.
 */
int hash_crc16_x25_finalize( void *h ) {
    int rc = 0;
    CRC16_X25 *crc = dynamic_cast<CRC16_X25 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = 1;
        crc->finalize( );
    }

    return rc;
}

/**
 * @brief Retrieves the hashing value after the last  <tt>hash_crc16_25_finalize</tt>
 * function call.
 *
 * The result of calling this method prior to the {@link hash_crc16_x25_finalize} method is
 * undefined. If the memory buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * If <tt>h</tt> is not a valid CRC-16-X25 handler, the function returns immediately.
 *
 * @param h    Pointer to a valid CRC-16-X25 handler.
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int hash_crc16_x25_get_value( void *h, uint8_t *buf, size_t len ) {
    int rc = 0;
    CRC16_X25 *crc = dynamic_cast<CRC16_X25 *> ( (HashingBase *) h );

    if(  crc != NULL ) {

        rc = crc->getValue( buf, len );
    }

    return rc;
}

/**
 * Destroys an existing CRC-16-X25 handler.
 *
 * @param h Pointer to a valid CRC-16-X25 handler. Cannot be <tt>NULL</tt>.
 *
 * @return a non-zero value on success or 0 on error.
 */
int hash_crc16_x25_destroy( void *h ) {
    int rc = 0;
    CRC16_X25 *crc = dynamic_cast<CRC16_X25 *> ( (HashingBase *) h );

    if(  crc != NULL ) {
        rc = 1;
        delete crc;
    }

    return rc;
}
// EOF: crc32.cpp
