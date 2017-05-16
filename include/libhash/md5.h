// ////////////////////////////////////////////////////////////////////////////
// System:     libHash
// File:       md5.h
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-21
//
// Description
// MD5 Security hashing algorithm declaration.
//
// Derived from the RSA Data Security, Inc.
// MD5 Message-Digest Algorithm
//
// Copyright (c) 2017, Yanick Poirier. All rights reserved.
// ////////////////////////////////////////////////////////////////////////////

#ifndef __LH_MD5_H00__
#   define __LH_MD5_H00__

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
 * @return always return 128.
 */
#   define hash_md5_get_size() 128

// ============================================================================
// STRUCTURES & TYPEDEFS
// ============================================================================

// ============================================================================
// CLASSES
// ============================================================================

#   ifdef __cplusplus
namespace libhash {

/**
 * This class implements the MD5 Message-Digest algorithm as defined by the 
 * RFC-1321. It provides a 128-bits hash fingerprint. 
 *
 * Security considerations on using MD5 have been updated by the RFC-6151. 
 *
 * @author Yanick Poirier (2017/01/21) 
 *  
 * @see <a href="https://tools.ietf.org/html/rfc1321">RFC-1321</a>
 * @see <a href="https://tools.ietf.org/html/rfc6151">RFC-6151</a>
 */ 
class LIBHASH_API MD5 : public HashingBase {
public:
    MD5() : HashingBase( 128 ) {
    }

    virtual ~MD5() {
    }

    virtual void init();
    virtual void update( const void *data, size_t size );
    virtual void finalize();

protected:
    void transform( uint8_t *block );

private:
    /** Current hashing state. */
    uint32_t    mState[4];

    /** Number of bits % 2^64 lsb first. */
    uint32_t    mBitCount[2];

    /** Current input data buffer. */
    uint8_t     mBlock[64];

};
};  // namespace libhash

#   endif  // __cplusplus

// ============================================================================
// PROTOTYPES
// ============================================================================

#   ifdef __cplusplus
extern "C" {
#   endif

void LIBHASH_API* hash_md5_create();
int LIBHASH_API hash_md5_init( void *h );
int LIBHASH_API hash_md5_update( void *h, void *buf, size_t len );
int LIBHASH_API hash_md5_finalize( void *h );
int LIBHASH_API hash_md5_get_value( void *h, uint8_t *buf, size_t len );
int LIBHASH_API hash_md5_destroy( void *h );

#ifdef __cplusplus
}   // extern "C"
#endif

#endif   // __LH_MD5_H00__

// EOF: md5.h

