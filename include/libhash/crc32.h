// ////////////////////////////////////////////////////////////////////////////
// System:     libHash
// File:       crc32.h
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-03-20
//
// Description CRC-32 hashing algorithm declaration.
//
// Copyright (c) 2017, Yanick Poirier. All rights reserved.
// ////////////////////////////////////////////////////////////////////////////

#ifndef __LH_CRC32_H00__
#   define __LH_CRC32_H00__

// ============================================================================
// HEADER FILES
// ============================================================================

#   include <libhash/defs.h>
#   include <libhash/hashbase.h>

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

/**
 * @brief Retrieves the size of the hash algorithm in bits.
 *
 * @return always return 32.
 */
#   define hash_crc32_get_size() 32

// ============================================================================
// STRUCTURES & TYPEDEFS
// ============================================================================

// ============================================================================
// CLASSES
// ============================================================================

#   ifdef __cplusplus
namespace libhash {

/**
 * @brief CRC32 algorithm as defined by RFC-1952. It provides a 32-bits hash
 * fingerprint.
 *
 * @author Yanick Poirier (2017/03/20) 
 *  
 * @see https://tools.ietf.org/html/rfc1952 
 */
class LIBHASH_API CRC32 : public HashingBase {
public:
    CRC32();
    virtual ~CRC32();

    virtual void init();
    virtual void update( const void *data, size_t size );
    virtual void finalize();

protected:

private:
    /** Current hashing state. */
    uint32_t    mState;

//    /** CRC-32 polynominal value. */
//    uint32_t    mPoly;
};
};  // namespace libhash

#   endif  // __cplusplus

// ============================================================================
// PROTOTYPES
// ============================================================================

#   ifdef __cplusplus
extern "C" {
#   endif

void LIBHASH_API* hash_crc32_create();
int LIBHASH_API hash_crc32_init( void *h );
int LIBHASH_API hash_crc32_update( void *h, void *buf, size_t len );
int LIBHASH_API hash_crc32_finalize( void *h );
int LIBHASH_API hash_crc32_get_value( void *h, uint8_t *buf, size_t len );
int LIBHASH_API hash_crc32_destroy( void *h );

#ifdef __cplusplus
}   // extern "C"
#endif

#endif   // __LH_CRC32_H00__

// EOF: crc32.h

