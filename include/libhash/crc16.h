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
// File:       crc16.h
//
// Author:     Yanick Poirier
// Date:       2019-11-09
//
// Description
// CRC-16 hashing algorithm declaration.
//=============================================================================

#ifndef __LH_CRC16_H00__
#    define __LH_CRC16_H00__

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CONSTANTS & MACROS
//-----------------------------------------------------------------------------

/**
 * @brief Retrieves the size of the hash algorithm in bits.
 *
 * @return always return 16.
 */
#    define hash_crc16_get_size() 32

//-----------------------------------------------------------------------------
// STRUCTURES & TYPEDEFS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

#    ifdef __cplusplus
namespace libhash {

/**
 * @brief Base class for all CRC-16 based algorithm.
 *
 * Note: All derived classes must used the reverse polynomial in order to create the
 * correct lookup tables.
 */
class LIBHASH_API CRC16Base : public CRCBase {
public:
    virtual ~CRC16Base( );

    virtual void init( );
    virtual void finalize( );

    inline uint16_t getXorValue( ) {
        return mXorValue;
    }

    inline uint16_t getPolynomial( ) {
        return mPolynomial;
    }

    inline uint16_t getInitialValue( ) {
        return mInit;
    }

protected:
    CRC16Base( uint16_t, uint16_t, uint16_t, bool, bool );

    void update( uint16_t *, const void *, size_t );
    void initLookupTable( uint16_t * );

    /** Current hashing state. */
    uint16_t    mState;

private:
    uint16_t mInit;
    uint16_t mPolynomial;
    uint16_t mXorValue;
    bool mInReflection;
    bool mOutReflection;

} ; // class CRC32Base

/**
 * @brief CRC16-CCITT algorithm.
 *
 * It provides a 16-bits hash fingerprint. It is sometimes called CRC-16 CCITT-FALSE
 *
 * Note: The first time a CRC-16 object is created, the constructor also builds the lookup
 * table so the it will take a little more as the  subsequent object creation.
 *
 * @author Yanick Poirier (2019/11/09)
 *
 * @see CRC16_X25
 */
class LIBHASH_API CRC16_CCITT : public CRC16Base {
public:
    CRC16_CCITT( );
    virtual ~CRC16_CCITT( );

    virtual void update( const void *data, size_t size );
    //    virtual void finalize( );

protected:

private:
    /** CRC lookup table */
    static uint16_t msLookup[ 256 ];
    static bool msTableInit;
} ;  // class CRC16_CCITT

/**
 * @brief CRC16-XModem algorithm.
 *
 * It provides a 16-bits hash fingerprint. It is sometimes called CRC-16 CCITT-ZERO
 *
 * Note: The first time a CRC-16 object is created, the constructor also builds the lookup
 * table so the it will take a little more as the  subsequent object creation.
 *
 * @author Yanick Poirier (2019/11/09)
 *
 * @see CRC16_X25
 */
class LIBHASH_API CRC16_XModem : public CRC16Base {
public:
    CRC16_XModem( );
    virtual ~CRC16_XModem( );

    virtual void update( const void *data, size_t size );
    //    virtual void finalize( );

protected:

private:
    /** CRC lookup table */
    static uint16_t msLookup[ 256 ];
    static bool msTableInit;
} ;  // class CRC16_XModem

/**
 * @brief A CRC16-X25 implementation.
 *
 * Note: The first time a CRC-16 object is created, the constructor also builds the lookup
 * table so the it will take a little more as the  subsequent object creation.
 *
 * @author Yanick Poirier (2019/11/09)
 *
 * @see CRC32
 */
class LIBHASH_API CRC16_X25 : public CRC16Base {
public:
    CRC16_X25( );
    virtual ~CRC16_X25( );

    virtual void update( const void *data, size_t size );
    //    virtual void finalize( );

protected:

private:
    /** CRC lookup table */
    static uint16_t msLookup[ 256 ];
    static bool msTableInit;

} ;  // class CRC16_X25

};  // namespace libhash


#    endif  // __cplusplus

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

#    ifdef __cplusplus
extern "C" {
#    endif

void LIBHASH_API* hash_crc16_ccitt_create( );
int LIBHASH_API hash_crc16_ccitt_init( void *h );
int LIBHASH_API hash_crc16_ccitt_update( void *h, void *buf, size_t len );
int LIBHASH_API hash_crc16_ccitt_finalize( void *h );
int LIBHASH_API hash_crc16_ccitt_get_value( void *h, uint8_t *buf, size_t len );
int LIBHASH_API hash_crc16_ccitt_destroy( void *h );

void LIBHASH_API* hash_crc16_xmodem_create( );
int LIBHASH_API hash_crc16_xmodem_init( void *h );
int LIBHASH_API hash_crc16_xmodem_update( void *h, void *buf, size_t len );
int LIBHASH_API hash_crc16_xmodem_finalize( void *h );
int LIBHASH_API hash_crc16_xmodem_get_value( void *h, uint8_t *buf, size_t len );
int LIBHASH_API hash_crc16_xmodem_destroy( void *h );

void LIBHASH_API* hash_crc16_x25_create( );
int LIBHASH_API hash_crc16_x25_init( void *h );
int LIBHASH_API hash_crc16_x25_update( void *h, void *buf, size_t len );
int LIBHASH_API hash_crc16_x25_finalize( void *h );
int LIBHASH_API hash_crc16_x25_get_value( void *h, uint8_t *buf, size_t len );
int LIBHASH_API hash_crc16_x25_destroy( void *h );

#    ifdef __cplusplus
}   // extern "C"
#    endif

#endif   // __LH_CRC16_H00__

// EOF: crc16.h