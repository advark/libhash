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
class LIBHASH_API CRC32Base : public HashingBase {
public:

    CRC32Base( uint32_t initValue, uint32_t polynomial );

    virtual ~CRC32Base( );

    virtual void init( );
    virtual void finalize( );

protected:
    virtual void update( uint32_t *lookupTable, const void *data, size_t size );
    void initLookupTable( uint32_t *table );

    /** Current hashing state. */
    uint32_t    mState;

private:
    uint32_t mInit;
    uint32_t mPolynomial;

} ; // class CRC32Base

/**
 * @brief CRC32 algorithm as defined by RFC-1952. It provides a 32-bits hash fingerprint.
 *
 * @author Yanick Poirier (2017/03/20)
 *
 * @see https://tools.ietf.org/html/rfc1952
 * @see CRC32C
 */
class LIBHASH_API CRC32 : public CRC32Base {
public:
    CRC32( );
    virtual ~CRC32( );

    virtual void update( const void *data, size_t size );
    virtual void finalize( );

protected:

private:
    /** CRC lookup table */
    static uint32_t msLookup[ 256 ];
    static bool msTableInit;
} ;  // class CRC32

/**
 * @brief A CRC32-C implementation.
 *
 * CRC32-C is becoming more popular because of its hardware implementation on some Intel's
 * processor. This class does not use the hardware features of those processor.
 *
 * @author Yanick Poirier (2019/11/02)
 *
 * @see CRC32
 */
class LIBHASH_API CRC32C : public CRC32Base {
public:
    CRC32C( );
    virtual ~CRC32C( );

    virtual void update( const void *data, size_t size );
    virtual void finalize( );

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

