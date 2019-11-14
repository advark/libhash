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
// File:       hashbase.h
//
// Author:     Yanick Poirier
// Date:       2017-01-21
//
// Description
// Declaration of the base hashing class.
//=============================================================================

#ifndef __LH_HASHBASE_H00__
#    define __LH_HASHBASE_H00__

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

#    include <stdint.h>

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
 * This is the base class of all hashing algorithm implementation. A hashing function,
 * also called @a Digest or @a Message @a Digest, hashes data into a numerical value of a
 * predefined length. The hash value is also called a @a fingerprint. The longer the hash
 * value, the less likely a collision will occur between 2 different input sets of data.
 *
 * The main use of hashing function is in cryptography where a message can be hashed into
 * a smaller value to ensure its integrity. Received data can be hashed into a value that
 * can be compared to the original hash value. If both matches the data is intact. If not,
 * the received data has been modified somehow.
 *
 * A hash value cannot be used to reconstruct the original data.
 *
 * @author Yanick Poirier (2017/01/21)
 */
class LIBHASH_API HashingBase {
public:
    /**
     * Destructor.
     */
    virtual ~HashingBase( );

    /**
     * @pure
     * @brief Initializes the hashing algorithm.
     *
     * This method must be called prior to any calls to {@link update} or
     * {@link finalize} methods.
     *
     */
    virtual void init( ) = 0;

    /**
     * @pure
     * @brief Updates the hash value with the specified data.
     *
     * If this method is called before {@link init} or after {@link finalize}, the result
     * is undefined.
     *
     * @param data Data to update the hash value with.
     * @param size Number of bytes in the data.
     */
    virtual void update( const void *data, size_t size ) = 0;

    /**
     * @brief Updates the hash value with the specified data.
     *
     * If this method is called before {@link init} or after {@link finalize}, the result
     * is undefined.
     *
     * @param data Single byte value to update the hash value with.
     */
    inline void update( uint8_t data ) {
        update( &data, 1 );
    }

    /**
     * @pure
     * Finalizes the hash value. Once this method is called any further call to
     * {@link update} methods is undefined.
     */
    virtual void finalize( ) = 0;

    /**
     * Retrieves the size of the hash algorithm in bits.
     *
     * @return the number of bits that compose the hashing result.
     */
    inline size_t getHashSize( ) {
        return mBits;
    }

    /**
     * @brief Retrieves the hashing value after the {@link finalize} method has been
     * called.
     *
     * The result of calling this method prior to the {@link finalize} method is
     * undefined.
     *
     * If the memory buffer is smaller than the hash size, only the higher part of the
     * hash value is returned.
     *
     * @param buffer Output buffer to receive the hashing result. The MSB is store at
     *               <tt<buffer[0]</tt> while LSB is at <tt>buffer[size - 1]</tt>.
     * @param size   Size of the output buffer in bytes.
     *
     * @return the number of byte copied to the <tt>buffer</tt>. To ensure the hash value
     *         is not truncate, the returned value must be equal to <tt>getHashSize() /8</tt>.
     */
    int getValue( uint8_t *buffer, size_t size );

protected:
    /**
     * Constructs a hashing object. Upon its construction, the hashing object is not
     * considered initialized for hashing computation yet.
     *
     * @param size Number of bits of the resulting hashing algorithm.
     */
    HashingBase( size_t size );


    /** Last calculated hash value. */
    uint8_t *mHash;

private:
    /** Number of bits of the hashing value. */
    size_t mBits;

} ; // class HashingBase

/**
 * This is the base class for Cyclic Redundency Check algorithms
 */
class LIBHASH_API CRCBase : public HashingBase {
public:

    virtual ~CRCBase( ) { }

    inline bool isInputReflected( ) {
        return mInReflection;
    }

    inline bool isOutputReflected( ) {
        return mOutReflection;
    }


protected:

    /**
     *
     * @param size          Number of bits of the resulting CRC algorithm.
     * @param inReflect     Input reflection flag. If <tt>true</tt>, the input data is
     *                      reflected before use.
     * @param outReflect    Output reflection flag. If <tt>true</tt>, the output value is
     *                      reflected.
     */
    CRCBase( size_t size, bool inReflect, bool outReflect ) : HashingBase( size ) {
        mInReflection = inReflect;
        mOutReflection = outReflect;
    };

    /**
     * @brief Returns the reflected 32-bits value of the specified value.
     *
     * A reflected value is a value where each bit are swapped. For example, the reflected
     * value of 0x55 (0b01010101) is 0xAA (0b10101010), 0x87 (0b10000111) is 0xE1
     * (0b11100001), etc.
     *
     * @param value Initial 32-bits value.
     *
     * @return the reflected value.
     */
    inline uint32_t reflect( uint32_t value ) {
        uint32_t tmp = 0;
        uint32_t loBit;
        uint32_t hiBit;
        for( int i = 0; i < 16; i++ ) {
            loBit = value & ( 1 << i );
            hiBit = value & ( 1 << ( 31 - i ) );
            tmp |= ( loBit << ( 31 - ( i * 2 ) ) );
            tmp |= ( hiBit >> ( 31 - ( i * 2 ) ) );
        }

        return tmp;
    }

    /**
     * @brief Returns the reflected 16-bits value of the specified value.
     *
     * A reflected value is a value where each bit are swapped. For example, the reflected
     * value of 0x55 (0b01010101) is 0xAA (0b10101010), 0x87 (0b10000111) is 0xE1
     * (0b11100001), etc.
     *
     * @param value Initial 16-bits value.
     *
     * @return the reflected value.
     */
    inline uint16_t reflect( uint16_t value ) {
        uint16_t tmp = 0;
        uint16_t loBit;
        uint16_t hiBit;

        for( int i = 0; i < 8; i++ ) {
            loBit = value & ( 1 << i );
            hiBit = value & ( 1 << ( 15 - i ) );
            if( loBit ) {
                tmp |= ( loBit << ( 15 - ( i * 2 ) ) );
            }
            if( hiBit ) {
                tmp |= ( hiBit >> ( 15 - ( i * 2 ) ) );
            }
        }

        return tmp;
    }

    /**
     * @brief Returns the reflected 8-bits value of the specified value.
     *
     * A reflected value is a value where each bit are swapped. For example, the reflected
     * value of 0x55 (0b01010101) is 0xAA (0b10101010), 0x87 (0b10000111) is 0xE1
     * (0b11100001), etc.
     *
     * @param value Initial 8-bits value.
     *
     * @return the reflected value.
     */
    inline uint8_t reflect( uint8_t value ) {
        uint8_t tmp = 0;
        uint8_t loBit;
        uint8_t hiBit;
        for( int i = 0; i < 4; i++ ) {
            loBit = value & ( 1 << i );
            hiBit = value & ( 1 << ( 7 - i ) );
            tmp |= ( loBit << ( 7 - ( i * 2 ) ) );
            tmp |= ( hiBit >> ( 7 - ( i * 2 ) ) );
        }

        return tmp;
    }

private:
    bool    mInReflection;
    bool    mOutReflection;

} ; // class CRCBase

};  // namespace libhash
#    endif  // __cplusplus

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

#endif   // __LH_HASHBASE_H00__

// EOF: hashbase.h

