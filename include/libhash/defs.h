// ////////////////////////////////////////////////////////////////////////////
// System:     libHash
// File:       defs.h
//
// Author:     Yanick Poirier       ypoirier@hotmail.com
// Date:       2017-01-21
//
// Description
// General definitions for libHash.
//
// Copyright (c) 2017, Yanick Poirier. All rights reserved.
// ////////////////////////////////////////////////////////////////////////////

#ifndef __LH_DEFS_H00__
#   define __LH_DEFS_H00__

#   ifndef __GNUC__
#       error "Unsupported compiler... Only g++ is supported."
#   endif

#   if __GNUC__ < 4
#       error "Require GCC 4.x or higher."
#   endif

// ============================================================================
// HEADER FILES
// ============================================================================

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

#   ifndef LIBHASH_API
#       ifdef __GNUC__
#           ifdef BUILD_LIBHASH
#               define LIBHASH_API  __attribute__ ((visibility ("default")))
#           else
#               define LIBHASH_API
#           endif  // ifdef BUILD_LIBHASH
#       endif  // ifdef __GNUC__
#   endif  // ifndef LIBHASH_API

// ============================================================================
// STRUCTURES & TYPEDEFS
// ============================================================================

#   define ROTR( n, b, s ) ((n >> b) | (n << (s - b)))
#   define ROTL( n, b, s ) ((n << b) | (n >> (s - b)))

// ============================================================================
// CLASSES
// ============================================================================

// ============================================================================
// PROTOTYPES
// ============================================================================

#endif   // __LH_DEFS_H00__

// EOF: defs.h

