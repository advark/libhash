// ////////////////////////////////////////////////////////////////////////////
// System:     libHash File:       hashbase.h
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-21
//
// Description
// Security hashing algorithm declarations.
//
// Derived from the RSA Data Security, Inc.
// MD5 Message-Digest Algorithm
//
// Copyright (c) 2017, Yanick Poirier. All rights reserved.
// ////////////////////////////////////////////////////////////////////////////

#ifndef __LH_HASHBASE_H00__
#   define __LH_HASHBASE_H00__

// ============================================================================
// HEADER FILES
// ============================================================================

#   include <stdint.h>
#   include <stdlib.h>
#   include <libhash/defs.h>

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

/**
 * This is the base class of all hashing algorithm
 * implementation. A hashing function, also called @a Digest
 * or @a Message @a Digest, hashes data into a numerical value
 * of a predefined length. The hash value is also called a
 * @a fingerprint. The longer the hash value, the less likely a
 * collision will occur between 2 different input sets of data.
 *
 * The main use of hashing function is in cryptography where a
 * message can be hashed into a smaller value to ensure its
 * integrity. Received data can be hashed into a value that can
 * be compared to the original hash value. If both matches the
 * data is intact. If not, the received data has been modified
 * somehow.
 *
 * A hash value cannot be used to reconstruct the original data.
 *
 * @author Yanick Poirier (2017/01/21)
 */
class LIBHASH_API HashingBase {
public:
    /**
     * Constructs a hashing object. Upon its construction, the
     * hashing object is not considered initialized for hashing
     * computation yet.
     *
     * @param size Number of bits of the resulting hashing
     *             algorithm.
     */
    HashingBase( size_t size );

    /**
     * Destructor.
     */
    virtual ~HashingBase();

    /**
     * @pure
     * @brief Initializes the hashing algorithm.
     *
     * This method must be called prior to any calls to
     * {@link update} or {@link finalize} methods.
     *
     */
    virtual void init() = 0;

    /**
     * @pure
     * @brief Updates the hash value with the specified data.
     *
     * If this method is called before {@link init} or after {@link
     * finalize}, the result is undefined.
     *
     * @param data Data to update the hash value with.
     * @param size Number of bytes in the data.
     */
    virtual void update( const void *data, size_t size ) = 0;

    /**
     * @brief Updates the hash value with the specified data.
     *
     * If this method is called before {@link init} or after
     * {@link finalize}, the result is undefined.
     *
     * @param data Single byte value to update the hash value with.
     */
    inline void update( uint8_t data ) {
        update( &data, 1 );
    }

    /**
     * @pure
     * Finalizes the hash value. Once this method is called any
     * further call to {@link update} methods is undefined.
     */
    virtual void finalize() = 0;

    /**
     * Retrieves the size of the hash algorithm in bits.
     *
     * @return the number of bits that compose the hashing result.
     */
    inline size_t getHashSize() {
        return mBits;
    }

    /**
     * @brief Retrieves the hashing value after the {@link finalize}
     *        method has been called.
     *
     * The result of calling this method prior to the {@link
     * finalize} method is undefined.
     *
     * If the memory buffer is smaller than the hash size, only the
     * higher part of the hash value is returned.
     *
     * @param buffer Output buffer to receive the hashing result.
     *               The MSB is store at <tt<buffer[0]</tt> while
     *               LSB is at <tt>buffer[size - 1]</tt>.
     * @param size   Size of the output buffer in bytes. 
     *  
     * @return the number of byte copied to the <tt>buffer</tt>.
     */
    int getValue( uint8_t *buffer, size_t size );

protected:

    /** Last calculated hash value. */
    uint8_t *mHash;

private:
    /** Number of bits of the hashing value. */
    size_t mBits;

};

};  // namespace libhash
#   endif  // __cplusplus

// ============================================================================
// PROTOTYPES
// ============================================================================

#endif   // __LH_HASHBASE_H00__

// EOF: hashbase.h

