# libHash
Copyright(c) 2017-19, Yanick Poirier

## Version History

0.1     Initial release
0.1.1   -Added CRC-32C
        -Fixed a bug in CRC-32
        -Fixed a bug in SHA2-224
        -Fixed a bug in SHA2-384
        -Merge all SHA2 algorithms in a single source file (sha2.cpp)
        -Move project to Netbeans 11 (removed libHash.gcc)

## Description
libHash is C/C++ library that provides a data hashing API. Supported algorithms are

* CRC32 as defined in [RFC-1952](https://tools.ietf.org/html/rfc1952)
* CRC32C is specified as the CRC that uses iSCSI polynomial in [RFC-3720](https://tools.ietf.org/html/rfc3720)
* MD5 as defined in [RFC-1321](https://tools.ietf.org/html/rfc1321)
* SHA-1 as defined in FIPS 180-2
* SHA-2 224-bits as defined in FIPS 180-2
* SHA-2 256-bits as defined in FIPS 180-2
* SHA-2 384-bits as defined in FIPS 180-2
* SHA-2 512-bits as defined in FIPS 180-2

CRCs are not hashing algorithms; they are checksum algorithms. CRCs are designed for error
detection and are usually implemented in communication protocols to detect accidental or
unintentional changes in data transmission such as noisy line for instance. They do however
share similarities with traditional hash methods. In all cases, these algorithms take a
chunk of data and reduce it to a smaller computed fix value (the size varies among
different algorithm). That is the reason why I have included CRC algorithm in this library.

Please note that this is a preliminary version. At this time, only GCC is supported and
was only tested on a Linux platform. However, the code can be easily ported to most of C++
compiler on almost any platform. A Windows version is planned as well as more hashing/CRC
algorithms may be included in future as time permits me to do so.

## License

libHash
Copyright (C) 2017-19 Yanick Poirier

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

More details about the licensing can be found [here](https://www.gnu.org/licenses/lgpl-3.0.en.html).
