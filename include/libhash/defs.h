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
// File:       defs.h
//
// Author:     Yanick Poirier
// Date:       2017-01-21
//
// Description
// General definitions for libHash.
//=============================================================================

#ifndef __LH_DEFS_H00__
#    define __LH_DEFS_H00__

#    ifndef __GNUC__ 
#        error "Unsupported compiler... Only g++ is supported."
#    endif

#    if __GNUC__ < 4
#        error "Require GCC 4.x or higher."
#    endif

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CONSTANTS & MACROS
//-----------------------------------------------------------------------------

#    ifndef LIBHASH_API
#        ifdef __GNUC__
#            ifdef BUILD_LIBHASH
#                define LIBHASH_API  __attribute__ ((visibility ("default")))
#            else
#                define LIBHASH_API
#            endif  // ifdef BUILD_LIBHASH
#        endif  // ifdef __GNUC__
#    endif  // ifndef LIBHASH_API

//-----------------------------------------------------------------------------
// STRUCTURES & TYPEDEFS
//-----------------------------------------------------------------------------

/**
 * @brief Unsigned right rotation.
 *
 * Rotates the value <tt>n</tt> <tt>s</tt> bits to the right. Right most bits (LSB) are
 * re-inserted on the left side (MSB).
 *
 * @param n     Value to rotate.
 * @param b     Total number of bits in <tt>n</tt>
 * @param s     Number of bits to rotate.
 *
 * @return the new <tt>n</tt> after the rotation.
 */
#    define ROTR( n, b, s ) ((n >> b) | (n << (s - b)))

/**
 * @brief Unsigned left rotation.
 *
 * Rotates the value <tt>n</tt> <tt>s</tt> bits to the left. Left most bits (MSB) are
 * re-inserted on the right side (LSB).
 *
 * @param n     Value to rotate.
 * @param b     Total number of bits in <tt>n</tt>
 * @param s     Number of bits to rotate.
 *
 * @return the new <tt>n</tt> after the rotation.
 */
#    define ROTL( n, b, s ) ((n << b) | (n >> (s - b)))

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

#endif   // __LH_DEFS_H00__

// EOF: defs.h

