// ////////////////////////////////////////////////////////////////////////////
// System:     Personal Accountant
// File:       sha1.h
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-24
//
// Description
// SHA-1 Security hashing algorithm declaration.
//
// Copyright (c) 2017, Yanick Poirier. All rights reserved.
// ////////////////////////////////////////////////////////////////////////////

#ifndef __LH_SHA1_H00__
#   define __LH_SHA1_H00__

// ============================================================================
// HEADER FILES
// ============================================================================

#include <libhash/defs.h>
#include <libhash/hashbase.h>

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

// ============================================================================
// STRUCTURES & TYPEDEFS
// ============================================================================

// ============================================================================
// CLASSES
// ============================================================================

#ifdef __cplusplus

namespace libhash {

/**
 * This class implements the SHA-1 Secure Hash Algorithm as
 * defined in the Federal Information Processing Standards
 * Publication 180-2 (FIPS 180-2) release August 1st, 2002.
 *
 * @author Yanick Poirier (2017/01/24)
 */
class LIBHASH_API SHA1 : public HashingBase {
public:
    /**
     * Constructor.
     */
    SHA1() : HashingBase( 160 ) {
    }

    /**
     * Desctructor.
     */
    virtual ~SHA1() {
    }

    /**
     * @copydoc HashingBase::init()
     */
    virtual void init();

    /**
     * @copydoc HashingBase::update( const void *, lhUInt32 )
     */
    virtual void update( const void *data, size_t size );

    /**
     * @copydoc HashingBase::finalize()
     */
    virtual void finalize();

protected:

    /**
     * Executes the SHA-1 transformation rounds.
     */
    void transform();

private:
    /** Current hashing state. */
    uint32_t    mState[5];

    /** Length of the message block in bits. */
    uint64_t    mBitCount;

    /** Current message block index. */
    size_t      mIndex;

    /** Message block. */
    uint8_t     mBlock[64];
};

};  // namespace libhash

// ============================================================================
// PROTOTYPES
// ============================================================================

#endif  // __cplusplus
        
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates a new SHA-1 handler.
 *
 * @return pointer to the newly created SHA-1 handler or
 *     <tt>null</tt> on error.
 */
LIBHASH_API void* hash_sha1_create();

/**
 * @brief Initializes the specified SHA-1 handler.
 *
 * This function prepares the SHA-1 handler for hashing data. It
 * must be called prior the first {@link hash_sha1_update} or 
 * {@link hash_sha1_final} calls. 
 *
 * @param h Pointer to a valid SHA-1 handler. Cannot be
 *          <tt>NULL</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *          valid.
 */
int LIBHASH_API hash_sha1_init( void *h );

/**
 * @brief Updates the specified SHA-1 handler's state with the
 *        data.
 *
 * This function updates the SHA-1 handler's state by hashing
 * data. It must be called after {@link hash_sha1_init} and 
 * before {@link hash_sha1_final}. The result of calling this 
 * function before {@link hash_sha1_init} or after {@link 
 * hash_sha1_final} is undefined. 
 *
 * @param h   Pointer to a valid SHA-1 handler. Cannot be
 *            <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha1_update( void *h, void *buf, size_t len );

/**
 * @brief Finalizes the specified SHA-1 handler's state.
 *
 * This function finalizes the SHA-1 handler's state and returns
 * the hashing value. It must be called after {@link 
 * hash_sha1_init} The result of calling this function before 
 * {@link hash_sha1_init} is undefined. 
 *
 * @param h   Pointer to a valid SHA-1 handler. Cannot be
 *            <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash
 *            value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha1_finalize( void *h );

/**
 * @brief Retrieves the hashing value after the last
 * <tt>hash_sha1_finalize</tt> function call.
 *
 * The result of calling this method prior to the {@link
 * hash_sha1_finalize} method is undefined. If the memory buffer
 * is smaller than the hash size, only the higher part of the
 * hash value is returned.
 *
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int LIBHASH_API hash_sha1_get_value( void *h, uint8_t *buf, size_t len );

/**
 * Destroys an existing SHA-1 handler.
 *
 * @param h Pointer to a valid SHA-1 handler. Cannot be
 *          <tt>NULL</tt>.
 * @return pointer to the newly created SHA-1 handler or
 *          <tt>null</tt> on error.
 */
int LIBHASH_API hash_sha1_destroy( void *h );

#ifdef __cplusplus
}   // extern "C"
#endif

#endif  // __LH_SHA1_H00__

// EOF: sha1.h
