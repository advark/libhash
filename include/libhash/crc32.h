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
// File:       crc32.h
//
// Author:     Yanick Poirier
// Date:       2017-03-20
//
// Description
// CRC-32 hashing algorithm declaration.
//=============================================================================

#ifndef __LH_CRC32_H00__
#    define __LH_CRC32_H00__

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CONSTANTS & MACROS
//-----------------------------------------------------------------------------

/**
 * @brief Retrieves the size of the hash algorithm in bits.
 *
 * @return always return 32.
 */
#    define hash_crc32_get_size() 32

//-----------------------------------------------------------------------------
// STRUCTURES & TYPEDEFS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

#    ifdef __cplusplus
namespace libhash {

/**
 * @brief Base class for all CRC-32 based algorithm.
 *
 * Note: All derived classes must used the reverse polynomial in order to create the
 * correct lookup tables.
 */
class LIBHASH_API CRC32Base : public CRCBase {
public:
    CRC32Base( uint32_t, uint32_t, uint32_t, bool, bool );
    virtual ~CRC32Base( );

    virtual void init( );
    virtual void finalize( );

    /**
     * Retrieves the value that will be XOR'ed with the final CRC.
     *
     * @return value to be XOR'ed
     */
    inline uint32_t getXorValue( ) {
        return mXorValue;
    }

    /**
     * Retrieves the polynomial used by this CRC.
     *
     * @return CRC's polynomial
     */
    inline uint32_t getPolynomial( ) {
        return mPolynomial;
    }

    /**
     * Retrieves the CRC's initial value.
     *
     * @return CRC's initial value.
     */
    inline uint32_t getInitialValue( ) {
        return mInit;
    }

protected:
    virtual void update( uint32_t *, const void *, size_t  );
    void initLookupTable( uint32_t * );

    /** Current hashing state. */
    uint32_t    mState;

private:
    uint32_t mInit;
    uint32_t mPolynomial;
    uint32_t mXorValue;

} ; // class CRC32Base

/**
 * @brief CRC32 algorithm as defined by RFC-1952.
 *
 * It provides a 32-bits hash fingerprint.
 *
 * Note: The first time a CRC-32 object is created, the constructor also builds the lookup
 * table so the it will take a little more as the  subsequent object creation. The main
 * reason is to avoid using memory that will not be needed if the class is not used. 1KB
 * may seems ridiculus on modern computer but may have huge impact on embedded systems.
 *
 * @author Yanick Poirier (2017/03/20)
 *
 * @see https://tools.ietf.org/html/rfc1952
 * @see CRC32C
 */
class LIBHASH_API CRC32 : public CRC32Base {
public:
    CRC32( );

    virtual ~CRC32( ) { };

    virtual void update( const void *data, size_t size );

protected:

private:
    /** CRC lookup table */
    static uint32_t msLookup[ 256 ];
    static bool msTableInit;
} ;  // class CRC32

/**
 * @brief CRC32 algorithm as defined by RFC-1952.
 *
 * It provides a 32-bits hash fingerprint.
 *
 * Note: The first time a CRC-32 object is created, the constructor also builds the lookup
 * table so the it will take a little more as the  subsequent object creation. The main
 * reason is to avoid using memory that will not be needed if the class is not used. 1KB
 * may seems ridiculus on modern computer but may have huge impact on embedded systems.
 *
 * @author Yanick Poirier (2017/03/20)
 *
 * @see https://tools.ietf.org/html/rfc1952
 * @see CRC32C
 */
class LIBHASH_API CRC32_BZip2 : public CRC32Base {
public:
    CRC32_BZip2( );

    virtual ~CRC32_BZip2( ) { };

    virtual void update( const void *data, size_t size );

protected:

private:
    /** CRC lookup table */
    static uint32_t msLookup[ 256 ];
    static bool msTableInit;
} ;  // class CRC32_BZip2

/**
 * @brief A CRC32-C implementation.
 *
 * CRC32-C is becoming more popular because of its hardware implementation on some Intel's
 * processor. This class does not use the hardware features of those processors.
 *
 * Note: The first time a CRC-32 object is created, the constructor also builds the lookup
 * table so the it will take a little more as the  subsequent object creation. The main
 * reason is to avoid using memory that will not be needed if the class is not used. 1KB
 * may seems ridiculus on modern computer but may have huge impact on embedded systems.
 *
 * @author Yanick Poirier (2019/11/02)
 *
 * @see CRC32
 */
class LIBHASH_API CRC32C : public CRC32Base {
public:
    CRC32C( );

    virtual ~CRC32C( ) { };

    virtual void update( const void *data, size_t size );

protected:

private:
    /** CRC lookup table */
    static uint32_t msLookup[ 256 ];
    static bool msTableInit;

} ;  // class CRC32C

};  // namespace libhash


#    endif  // __cplusplus

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

#    ifdef __cplusplus
extern "C" {
#    endif

void LIBHASH_API* hash_crc32_create( );
int LIBHASH_API hash_crc32_init( void *h );
int LIBHASH_API hash_crc32_update( void *h, void *buf, size_t len );
int LIBHASH_API hash_crc32_finalize( void *h );
int LIBHASH_API hash_crc32_get_value( void *h, uint8_t *buf, size_t len );
int LIBHASH_API hash_crc32_destroy( void *h );

void LIBHASH_API* hash_crc32c_create( );
int LIBHASH_API hash_crc32c_init( void *h );
int LIBHASH_API hash_crc32c_update( void *h, void *buf, size_t len );
int LIBHASH_API hash_crc32c_finalize( void *h );
int LIBHASH_API hash_crc32c_get_value( void *h, uint8_t *buf, size_t len );
int LIBHASH_API hash_crc32c_destroy( void *h );

#    ifdef __cplusplus
}   // extern "C"
#    endif

#endif   // __LH_CRC32_H00__

// EOF: crc32.h

