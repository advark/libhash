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
// File:       sha1.h
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-24
//
// Description
// SHA-1 Security hashing algorithm declaration.
//=============================================================================

#ifndef __LH_SHA1_H00__
#    define __LH_SHA1_H00__

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

//#    include <libhash/defs.h>
//#    include <libhash/hashbase.h>

//-----------------------------------------------------------------------------
// CONSTANTS & MACROS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// STRUCTURES & TYPEDEFS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

#    ifdef __cplusplus

namespace libhash {

/**
 * This class implements the SHA-1 Secure Hash Algorithm as defined in the Federal
 * Information Processing Standards Publication 180-2 (FIPS 180-2) release August 1st, 2002.
 *
 * @author Yanick Poirier (2017/01/24)
 */
class LIBHASH_API SHA1 : public HashingBase {
public:

    /**
     * Constructor.
     */
    SHA1( ) : HashingBase( 160 ) { }

    /**
     * Destructor.
     */
    virtual ~SHA1( ) { }

    virtual void init( );
    virtual void update( const void *data, size_t size );
    virtual void finalize( );

protected:
    void transform( );

private:
    /** Current hashing state. */
    uint32_t    mState[5];

    /** Length of the message block in bits. */
    uint64_t    mBitCount;

    /** Current message block index. */
    size_t      mIndex;

    /** Message block. */
    uint8_t     mBlock[64];
} ;

};  // namespace libhash

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

#    endif  // __cplusplus

#    ifdef __cplusplus
extern "C" {
#    endif

void* LIBHASH_API hash_sha1_create( );
int LIBHASH_API hash_sha1_init( void *h );
int LIBHASH_API hash_sha1_update( void *h, void *buf, size_t len );
int LIBHASH_API hash_sha1_finalize( void *h );
int LIBHASH_API hash_sha1_get_value( void *h, uint8_t *buf, size_t len );
int LIBHASH_API hash_sha1_destroy( void *h );

#    ifdef __cplusplus
}   // extern "C"
#    endif

#endif  // __LH_SHA1_H00__

// EOF: sha1.h
