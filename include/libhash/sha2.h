// ////////////////////////////////////////////////////////////////////////////
// System:     Personal Accountant
// File:       sha2.h
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-25
//
// Description
// SHA-2 Security hashing algorithm declarations.
//
// Copyright (c) 2017, Yanick Poirier. All rights reserved.
// ////////////////////////////////////////////////////////////////////////////

#ifndef __LH_SHA2_H00__
#   define __LH_SHA2_H00__

// ============================================================================
// HEADER FILES
// ============================================================================

#   include <libhash/defs.h>
#   include <libhash/hashbase.h>

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

// ============================================================================
// STRUCTURES & TYPEDEFS
// ============================================================================

// ============================================================================
// CLASSES
// ============================================================================

#   ifdef __cplusplus

namespace libhash {

// ----------------------------------------------------------------------------
/**
 *  This class implements the SHA-2 256-bits Secure Hash
 *  Algorithm as defined in the Federal Information Processing
 *  Standards Publication 180-2 (FIPS 180-2) release August 1st,
 *  2002.
 *
 * @author Yanick Poirier (2017/01/25)
 */
class LIBHASH_API SHA2_256 : public HashingBase {
public:
    SHA2_256() : HashingBase( 256 ) {
    }
    virtual ~SHA2_256() {
    }

    /**
     * @copydoc HashingBase::init()
     */
    virtual void init();

    /**
     * @copydoc HashingBase::update( const void *, size_t )
     */
    virtual void update( const void *data, size_t size );

    /**
     * @copydoc HashingBase::finalize()
     */
    virtual void finalize();

protected:
    SHA2_256( size_t bits ) : HashingBase( bits ) {
    }

    /** @copydoc */
    void transform();

    /**
     * Clears internal data after finalization.
     */
    void clear();

    /** Current digest state. */
    uint32_t    mState[8];

    /** Length of the message block in bits. */
    uint64_t    mBitCount;

    /** Current message block index. */
    size_t      mIndex;

    /** Current message block. */
    uint8_t     mBlock[64];
};

/**
 * This class implements the SHA-2 224-bits Secure Hash
 * Algorithm as defined in the FIPS 180-4 document released in
 * August 2015.
 *
 * @author Yanick Poirier (2017/01/25)
 */
class LIBHASH_API SHA2_224 : public SHA2_256 {
public:
    SHA2_224() : SHA2_256( 224 ) {
    }
    virtual ~SHA2_224() {
    }

    /**
     * @copydoc HashingBase::init()
     */
    virtual void init();

    /**
     * @copydoc HashingBase::finalize()
     */
    virtual void finalize();

protected:

};

// ----------------------------------------------------------------------------

/**
 *  This class implements the SHA-2 512-bits Secure Hash
 *  Algorithm as defined in the Federal Information Processing
 *  Standards Publication 180-2 (FIPS 180-2) release August 1st,
 *  2002.
 *
 * @author Yanick Poirier (2017/01/25)
 */
class LIBHASH_API SHA2_512 : public HashingBase {
public:
    SHA2_512() : HashingBase( 512 ) {
    }

    virtual ~SHA2_512() {
    }

    /**
     * @copydoc HashingBase::init()
     */
    virtual void init();

    /**
     * @copydoc HashingBase::update( const void *, size_t )
     */
    virtual void update( const void *data, size_t size );

    /**
     * @copydoc HashingBase::finalize()
     */
    virtual void finalize();

protected:
    SHA2_512( size_t bits ) : HashingBase( bits ) {
    }

    void transform();

    void clear();

    /** Current digest state. */
    uint64_t    mState[8];

    /** Length of the message block in bits. LSB is stored in
     *  offset 0. */
    uint64_t    mBitCount[2];

    /** Current message block index. */
    size_t      mIndex;

    /** Current message block. */
    uint8_t     mBlock[128];

};

// ----------------------------------------------------------------------------

/**
 * This class implements the SHA-2 384-bits Secure Hash
 * Algorithm as defined in the FIPS 180-4 document released in
 * August 2015.
 *
 * @author Yanick Poirier (2017/01/25)
 */
class LIBHASH_API SHA2_384 : public SHA2_512 {
public:
    //    using SHA2_512::update;

    SHA2_384() : SHA2_512( 384 ) {
    }
    virtual ~SHA2_384() {
    }

    /**
     * @copydoc HashingBase::init()
     */
    virtual void init();

    /**
     * @copydoc HashingBase::update( const void *, size_t )
     */
    //    virtual void update( const void *data, size_t size );

    /**
     * @copydoc HashingBase::finalize()
     */
    virtual void finalize();

protected:
};

};  // namespace libhash

#   endif  // __cplusplus

// ============================================================================
// PROTOTYPES
// ============================================================================

#   ifdef __cplusplus
extern "C" {
#   endif

/**
 * Creates a new SHA2-224 handler.
 *
 * @return pointer to the newly created SHA2-224 handler or
 *     <tt>null</tt> on error.
 */
void LIBHASH_API* hash_sha2_224_create();

/**
 * @brief Initializes the specified SHA2-224 handler.
 *
 * This function prepares the SHA2-224 handler for hashing data.
 * It must be called prior the first {@link
 * hash_sha2_224_update} or {@link hash_sha2_224_final} calls.
 *
 * @param h Pointer to a valid SHA2-224 handler. Cannot be
 *          <tt>NULL</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *          valid.
 */
int LIBHASH_API hash_sha2_224_init( void *h );

/**
 * @brief Updates the specified SHA2-224 handler's state with
 *        the data.
 *
 * This function updates the SHA2-224 handler's state by hashing
 * data. It must be called after {@link hash_sha2_224_init} and
 * before {@link hash_sha2_224_final}. The result of calling
 * this function before {@link hash_sha2_224_init} or after
 * {@link hash_sha1_final} is undefined.
 *
 * @param h   Pointer to a valid SHA2-224 handler. Cannot be
 *            <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha2_224_update( void *h, void *buf, size_t len );

/**
 * @brief Finalizes the specified SHA2-224 handler's state.
 *
 * This function finalizes the SHA2-224 handler's state and
 * returns the hashing value. It must be called after {@link
 * hash_sha2_224_init} The result of calling this function
 * before {@link hash_sha2_224_init} is undefined.
 *
 * @param h   Pointer to a valid SHA2-224 handler. Cannot be
 *            <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash
 *            value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha2_224_finalize( void *h );

/**
 * @brief Retrieves the hashing value after the last
 * <tt>buffer[</tt> method call.
 *
 * The result of calling this method prior to the {@link
 * hash_sha2_224_finalize} method is undefined. If the memory
 * buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int LIBHASH_API hash_sha2_224_get_value( void *h, uint8_t *buf, size_t len );

/**
 * Destroys an existing SHA2-224 handler.
 *
 * @param h Pointer to a valid SHA2-224 handler. Cannot be
 *          <tt>NULL</tt>.
 * @return pointer to the newly created SHA2-224 handler or
 *          <tt>null</tt> on error.
 */
int LIBHASH_API hash_sha2_224_destroy( void *h );

/**
 * Creates a new SHA2-256 handler.
 *
 * @return pointer to the newly created SHA2-256 handler or
 *     <tt>null</tt> on error.
 */
void LIBHASH_API* hash_sha2_256_create();

/**
 * @brief Initializes the specified SHA2-256 handler.
 *
 * This function prepares the SHA2-256 handler for hashing data.
 * It must be called prior the first {@link
 * hash_sha2_256_update} or {@link hash_sha2_256_final} calls.
 *
 * @param h Pointer to a valid SHA2-256 handler. Cannot be
 *          <tt>NULL</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *          valid.
 */
int LIBHASH_API hash_sha2_256_init( void *h );

/**
 * @brief Updates the specified SHA2-256 handler's state with
 *        the data.
 *
 * This function updates the SHA2-256 handler's state by hashing
 * data. It must be called after {@link hash_sha2_256_init} and
 * before {@link hash_sha2_256_final}. The result of calling
 * this function before {@link hash_sha2_256_init} or after
 * {@link hash_sha1_final} is undefined.
 *
 * @param h   Pointer to a valid SHA2-256 handler. Cannot be
 *            <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha2_256_update( void *h, void *buf, size_t len );

/**
 * @brief Finalizes the specified SHA2-256 handler's state.
 *
 * This function finalizes the SHA2-256 handler's state and
 * returns the hashing value. It must be called after {@link
 * hash_sha2_256_init} The result of calling this function
 * before {@link hash_sha2_256_init} is undefined.
 *
 * @param h   Pointer to a valid SHA2-256 handler. Cannot be
 *            <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash
 *            value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha2_256_finalize( void *h );

/**
 * @brief Retrieves the hashing value after the last
 * <tt>buffer[</tt> method call.
 *
 * The result of calling this method prior to the {@link
 * hash_sha2_256_finalize} method is undefined. If the memory
 * buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int LIBHASH_API hash_sha2_256_get_value( void *h, uint8_t *buf, size_t len );

/**
 * Destroys an existing SHA2-256 handler.
 *
 * @param h Pointer to a valid SHA2-256 handler. Cannot be
 *          <tt>NULL</tt>.
 * @return pointer to the newly created SHA22-256 handler or
 *          <tt>null</tt> on error.
 */
int LIBHASH_API hash_sha2_256_destroy( void *h );

/**
 * Creates a new SHA2-384 handler.
 *
 * @return pointer to the newly created SHA2-384 handler or
 *     <tt>null</tt> on error.
 */
void LIBHASH_API* hash_sha2_384_create();

/**
 * @brief Initializes the specified SHA2-256 handler.
 *
 * This function prepares the SHA2-384 handler for hashing data.
 * It must be called prior the first {@link
 * hash_sha2_384_update} or {@link hash_sha2_384_final} calls.
 *
 * @param h Pointer to a valid SHA2-384 handler. Cannot be
 *          <tt>NULL</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *          valid.
 */
int LIBHASH_API hash_sha2_384_init( void *h );

/**
 * @brief Updates the specified SHA2-384 handler's state
 *        with the data.
 *
 * This function updates the SHA2-384 bits handler's state by
 * hashing data. It must be called after {@link
 * hash_sha2_384_init} and before {@link hash_sha2_384_final}.
 * The result of calling this function before {@link
 * hash_sha2_384_init} or after {@link hash_sha1_final} is
 * undefined.
 *
 * @param h   Pointer to a valid SHA2-384 bits handler. Cannot
 *            be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha2_384_update( void *h, void *buf, size_t len );

/**
 * @brief Finalizes the specified SHA2-384 handler's state.
 *
 * This function finalizes the SHA2-384 handler's state and
 * returns the hashing value. It must be called after {@link
 * hash_sha2_384_init} The result of calling this function
 * before {@link hash_sha2_384_init} is undefined.
 *
 * @param h   Pointer to a valid SHA2-384 handler. Cannot be
 *            <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash
 *            value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha2_384_finalize( void *h );

/**
 * @brief Retrieves the hashing value after the last
 * <tt>buffer[</tt> method call.
 *
 * The result of calling this method prior to the {@link
 * hash_sha2_384_finalize} method is undefined. If the memory
 * buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int LIBHASH_API hash_sha2_384_get_value( void *h, uint8_t *buf, size_t len );

/**
 * Destroys an existing SHA2-384 handler.
 *
 * @param h Pointer to a valid SHA2-384 handler. Cannot be
 *          <tt>NULL</tt>.
 * @return pointer to the newly created SHA2-384 handler or
 *          <tt>null</tt> on error.
 */
int LIBHASH_API hash_sha2_384_destroy( void *h );

/**
 * Creates a new SHA2-512 handler.
 *
 * @return pointer to the newly created SHA2-512 handler or
 *     <tt>null</tt> on error.
 */
void LIBHASH_API* hash_sha2_512_create();

/**
 * @brief Initializes the specified SHA2-512 handler.
 *
 * This function prepares the SHA2-512 handler for hashing data.
 * It must be called prior the first {@link
 * hash_sha2_512_update} or {@link hash_sha2_512_final} calls.
 *
 * @param h Pointer to a valid SHA2-512 handler. Cannot be
 *          <tt>NULL</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *          valid.
 */
int LIBHASH_API hash_sha2_512_init( void *h );

/**
 * @brief Updates the specified SHA2-512 handler's state with
 *        the data.
 *
 * This function updates the SHA2-512 bits handler's state by
 * hashing data. It must be called after {@link
 * hash_sha2_512_init} and before {@link hash_sha2_384_final}.
 * The result of calling this function before {@link
 * hash_sha2_512_init} or after {@link hash_sha2_512_final} is
 * undefined.
 *
 * @param h   Pointer to a valid SHA2-512 bits handler. Cannot
 *            be <tt>NULL</tt>.
 * @param buf Pointer to a set of data to hash.
 * @param len Number of bytes in <tt>buf</tt> to hash.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha2_512_update( void *h, void *buf, size_t len );

/**
 * @brief Finalizes the specified SHA2-512 handler's state.
 *
 * This function finalizes the SHA2-512 handler's state and
 * returns the hashing value. It must be called after {@link
 * hash_sha2_512_init} The result of calling this function
 * before {@link hash_sha2_512_init} is undefined.
 *
 * @param h   Pointer to a valid SHA2-384 handler. Cannot be
 *            <tt>NULL</tt>.
 * @param buf Pointer to buffer to receive the calculated hash
 *            value.
 * @param len Number of bytes in <tt>buf</tt>.
 *
 * @return a non-zero value on success of 0 if <tt>h</tt> is not
 *            valid.
 */
int LIBHASH_API hash_sha2_512_finalize( void *h );

/**
 * @brief Retrieves the hashing value after the last
 * <tt>buffer[</tt> method call.
 *
 * The result of calling this method prior to the {@link
 * hash_sha2_512_finalize} method is undefined. If the memory
 * buffer is smaller than the hash size, only the higher part of
 * the hash value is returned.
 *
 * @param buf  Memory buffer to receive the hashing result.
 * @param size Size of the memory buffer in bytes.
 *
 * @return the number of bytes copied into <tt>buf</tt>.
 */
int LIBHASH_API hash_sha2_512_get_value( void *h, uint8_t *buf, size_t len );
/**
 * Destroys an existing SHA2-512 handler.
 *
 * @param h Pointer to a valid SHA2-512 handler. Cannot be
 *          <tt>NULL</tt>.
 * @return pointer to the newly created SHA2-512 handler or
 *          <tt>null</tt> on error.
 */
int LIBHASH_API hash_sha2_512_destroy( void *h );

#ifdef __cplusplus
}
#endif

#endif   // __LH_SHA2_H00__

// EOF: sha2.h
