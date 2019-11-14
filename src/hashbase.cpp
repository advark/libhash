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
// File:       hashbase.cpp
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-21
//
// Description
// HashingBase class implementation
//=============================================================================

//-----------------------------------------------------------------------------
// HEADER FILES
//-----------------------------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>
#include "../include/libhash/defs.h"
#include "../include/libhash/hashbase.h"

using namespace libhash;

//-----------------------------------------------------------------------------
// CONSTANTS & MACROS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// STRUCTURES & TYPEDEFS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// CLASSES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// IMPLEMENTATION
//-----------------------------------------------------------------------------

HashingBase::HashingBase( size_t size ) {
    mBits = size;
    mHash = ( uint8_t * )::malloc( size / 8 );
}

HashingBase::~HashingBase( ) {
    if( mHash != NULL ) {
        ::free( mHash );
    }
}

int HashingBase::getValue( uint8_t *buffer, size_t size ) {
    size_t hashBytes = getHashSize( ) / 8;
    size_t max = size < hashBytes ? size : hashBytes;

    for( size_t i = 0; i < max; i++ ) {
        buffer[ i ] = mHash[ i ];
    }

    return max;
}

// EOF: hashbase.cpp


