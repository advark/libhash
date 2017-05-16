#include <libhash/libhash.h>

#include <stdio.h>
#include <string.h>

struct _test_data {
    char *title;
    void *data;
    size_t size;
    uint8_t expected_md5[16];
    uint8_t expected_sha1[20];
    uint8_t expected_sha2_256[32];
    uint8_t expected_sha2_512[64];
};

struct _test_data testdata[] = {
    { "  Empty string", "", 0,
        /* MD5 */
        { 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e },
        /* SHA-1 */
        { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
            0xaf, 0xd8, 0x07, 0x09 },
        /* SHA-2 256 */
        { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 },
        /* SHA-2 512 */
        { 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e }
    },
    { "  a", "a", 1,
        /* MD5 */
        { 0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61 },
        /* SHA-1 */
        { 0x86, 0xf7, 0xe4, 0x37, 0xfa, 0xa5, 0xa7, 0xfc, 0xe1, 0x5d, 0x1d, 0xdc, 0xb9, 0xea, 0xea, 0xea,
            0x37, 0x76, 0x67, 0xb8 },
        /* SHA-2 256 */
        { 0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca, 0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23, 0xdc, 0x4d,
            0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72, 0xb9, 0x80, 0x77, 0x85, 0xaf, 0xee, 0x48, 0xbb },
        /* SHA-2 512 */
        { 0x1f, 0x40, 0xfc, 0x92, 0xda, 0x24, 0x16, 0x94, 0x75, 0x09, 0x79, 0xee, 0x6c, 0xf5, 0x82, 0xf2,
            0xd5, 0xd7, 0xd2, 0x8e, 0x18, 0x33, 0x5d, 0xe0, 0x5a, 0xbc, 0x54, 0xd0, 0x56, 0x0e, 0x0f, 0x53,
            0x02, 0x86, 0x0c, 0x65, 0x2b, 0xf0, 0x8d, 0x56, 0x02, 0x52, 0xaa, 0x5e, 0x74, 0x21, 0x05, 0x46,
            0xf3, 0x69, 0xfb, 0xbb, 0xce, 0x8c, 0x12, 0xcf, 0xc7, 0x95, 0x7b, 0x26, 0x52, 0xfe, 0x9a, 0x75 }
    },
    { "  abc", "abc", 3,
        /* MD5 */
        { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 },
        /* SHA-1 */
        { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
            0x9c, 0xd0, 0xd8, 0x9d },
        /* SHA-2 256 */
        { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad },
        /* SHA-2 512 */
        { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f }
    },
    { "  56 bytes message", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        /* MD5 */
        { 0x82, 0x15, 0xef, 0x07, 0x96, 0xa2, 0x0b, 0xca, 0xaa, 0xe1, 0x16, 0xd3, 0x87, 0x6c, 0x66, 0x4a },
        /* SHA-1 */
        { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xAe, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5,
            0xe5, 0x46, 0x70, 0xf1 },
        /* SHA-2 256 */
        { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
            0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 },
        /* SHA-2 512 */
        { 0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
            0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
            0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
            0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45 }
    },
    { "  112 bytes message",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        112,
        /* MD5 */
        { 0x03, 0xdd, 0x88, 0x07, 0xa9, 0x31, 0x75, 0xfb, 0x06, 0x2d, 0xfb, 0x55, 0xdc, 0x7d, 0x35, 0x9c },
        /* SHA-1 */
        { 0xa4, 0x9b, 0x24, 0x46, 0xa0, 0x2c, 0x64, 0x5b, 0xf4, 0x19, 0xf9, 0x95, 0xb6, 0x70, 0x91, 0x25, 
            0x3a, 0x04, 0xa2, 0x59 },
        /* SHA-2 256 */
        { 0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
            0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1 },
        /* SHA-2 512 */
        { 0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
            0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
            0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
            0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09 }
    },
    { "  lowercase alphabet", "abcdefghijklmnopqrstuvwxyz", 26,
        /* MD5 */
        { 0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b },
        /* SHA-1 */
        { 0x32, 0xd1, 0x0c, 0x7b, 0x8c, 0xf9, 0x65, 0x70, 0xca, 0x04, 0xce, 0x37, 0xf2, 0xa1, 0x9d, 0x84,
            0x24, 0x0d, 0x3a, 0x89 },
        /* SHA-2 256 */
        { 0x71, 0xc4, 0x80, 0xdf, 0x93, 0xd6, 0xae, 0x2f, 0x1e, 0xfa, 0xd1, 0x44, 0x7c, 0x66, 0xc9, 0x52,
            0x5e, 0x31, 0x62, 0x18, 0xcf, 0x51, 0xfc, 0x8d, 0x9e, 0xd8, 0x32, 0xf2, 0xda, 0xf1, 0x8b, 0x73 },
        /* SHA-2 512 */
        { 0x4d, 0xbf, 0xf8, 0x6c, 0xc2, 0xca, 0x1b, 0xae, 0x1e, 0x16, 0x46, 0x8a, 0x05, 0xcb, 0x98, 0x81,
            0xc9, 0x7f, 0x17, 0x53, 0xbc, 0xe3, 0x61, 0x90, 0x34, 0x89, 0x8f, 0xaa, 0x1a, 0xab, 0xe4, 0x29,
            0x95, 0x5a, 0x1b, 0xf8, 0xec, 0x48, 0x3d, 0x74, 0x21, 0xfe, 0x3c, 0x16, 0x46, 0x61, 0x3a, 0x59,
            0xed, 0x54, 0x41, 0xfb, 0x0f, 0x32, 0x13, 0x89, 0xf7, 0x7f, 0x48, 0xa8, 0x79, 0xc7, 0xb1, 0xf1 }
    },
    { "  Lower/Upper case alphabet & digits", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
        /* MD5 */
        { 0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f },
        /* SHA-1 */
        { 0x76, 0x1c, 0x45, 0x7b, 0xf7, 0x3b, 0x14, 0xd2, 0x7e, 0x9e, 0x92, 0x65, 0xc4, 0x6f, 0x4b, 0x4d,
            0xda, 0x11, 0xf9, 0x40 },
        /* SHA-2 256 */
        { 0xdb, 0x4b, 0xfc, 0xbd, 0x4d, 0xa0, 0xcd, 0x85, 0xa6, 0x0c, 0x3c, 0x37, 0xd3, 0xfb, 0xd8, 0x80,
            0x5c, 0x77, 0xf1, 0x5f, 0xc6, 0xb1, 0xfd, 0xfe, 0x61, 0x4e, 0xe0, 0xa7, 0xc8, 0xfd, 0xb4, 0xc0 },
        /* SHA-2 512 */
        { 0x1e, 0x07, 0xbe, 0x23, 0xc2, 0x6a, 0x86, 0xea, 0x37, 0xea, 0x81, 0x0c, 0x8e, 0xc7, 0x80, 0x93,
            0x52, 0x51, 0x5a, 0x97, 0x0e, 0x92, 0x53, 0xc2, 0x6f, 0x53, 0x6c, 0xfc, 0x7a, 0x99, 0x96, 0xc4,
            0x5c, 0x83, 0x70, 0x58, 0x3e, 0x0a, 0x78, 0xfa, 0x4a, 0x90, 0x04, 0x1d, 0x71, 0xa4, 0xce, 0xab,
            0x74, 0x23, 0xf1, 0x9c, 0x71, 0xb9, 0xd5, 0xa3, 0xe0, 0x12, 0x49, 0xf0, 0xbe, 0xbd, 0x58, 0x94 }
    },
    { "  80 digits (1234567890 8 times)", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
        /* MD5 */
        { 0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a },
        /* SHA-1 */
        { 0x50, 0xab, 0xf5, 0x70, 0x6a, 0x15, 0x09, 0x90, 0xa0, 0x8b, 0x2c, 0x5e, 0xa4, 0x0f, 0xa0, 0xe5, 
            0x85, 0x55, 0x47, 0x32 },
        /* SHA-2 256 */
        { 0xf3, 0x71, 0xbc, 0x4a, 0x31, 0x1f, 0x2b, 0x00, 0x9e, 0xef, 0x95, 0x2d, 0xd8, 0x3c, 0xa8, 0x0e,
            0x2b, 0x60, 0x02, 0x6c, 0x8e, 0x93, 0x55, 0x92, 0xd0, 0xf9, 0xc3, 0x08, 0x45, 0x3c, 0x81, 0x3e },
        /* SHA-2 512 */
        { 0x72, 0xec, 0x1e, 0xf1, 0x12, 0x4a, 0x45, 0xb0, 0x47, 0xe8, 0xb7, 0xc7, 0x5a, 0x93, 0x21, 0x95,
            0x13, 0x5b, 0xb6, 0x1d, 0xe2, 0x4e, 0xc0, 0xd1, 0x91, 0x40, 0x42, 0x24, 0x6e, 0x0a, 0xec, 0x3a,
            0x23, 0x54, 0xe0, 0x93, 0xd7, 0x6f, 0x30, 0x48, 0xb4, 0x56, 0x76, 0x43, 0x46, 0x90, 0x0c, 0xb1,
            0x30, 0xd2, 0xa4, 0xfd, 0x5d, 0xd1, 0x6a, 0xbb, 0x5e, 0x30, 0xbc, 0xb8, 0x50, 0xde, 0xe8, 0x43 },
    },
    { "  1 Mb buffer filled with 'a'", NULL, 1000000,
        /* MD5 */
        { 0x77, 0x07, 0xd6, 0xae, 0x4e, 0x02, 0x7c, 0x70, 0xee, 0xa2, 0xa9, 0x35, 0xc2, 0x29, 0x6f, 0x21 },
        /* SHA-1 */
        { 0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31,
            0x65, 0x34, 0x01, 0x6f },
        /* SHA-2 256 */
        { 0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
            0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0 },
        /* SHA-2 512 */
        { 0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64, 0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63,
            0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28, 0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
            0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a, 0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b,
            0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e, 0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b }
    },
    { "  1 Kb buffer filled with '123456789'", NULL, 1000,
        /* MD5 */
        { 0x49, 0xef, 0x81, 0xb8, 0xcf, 0xca, 0x42, 0x60, 0x7c, 0x9f, 0x44, 0x5b, 0xe7, 0x18, 0x15, 0x7c },
        /* SHA-1 */
        { 0x5e, 0x5b, 0xb5, 0x7f, 0x50, 0xc4, 0xad, 0x3d, 0xac, 0x76, 0x50, 0xeb, 0xd0, 0xcd, 0x43, 0x54, 
            0xbd, 0x96, 0xca, 0xb3 },
        /* SHA-2 256 */
        { 0xe1, 0x7a, 0xe5, 0x51, 0x90, 0x86, 0x3f, 0x8d, 0x2c, 0x7e, 0x21, 0x3c, 0x20, 0x08, 0xef, 0x52, 
            0xb7, 0x11, 0x3a, 0xc7, 0x14, 0x33, 0x3e, 0x01, 0xa1, 0x6a, 0x16, 0xbf, 0x2c, 0x98, 0xe2, 0x10 },
        /* SHA-2 512 */
        { 0x6f, 0x59, 0x38, 0x7b, 0xf3, 0x9b, 0xcd, 0x4d, 0x20, 0xd5, 0x01, 0xaa, 0x90, 0xff, 0x84, 0xb5, 
            0x27, 0x9f, 0xaa, 0xe9, 0x05, 0x8c, 0xe4, 0x78, 0x0a, 0x36, 0xfa, 0x6b, 0xfb, 0x89, 0x3e, 0x54, 
            0x6b, 0xef, 0x3b, 0xa8, 0x17, 0xce, 0xa0, 0xc3, 0x6e, 0x77, 0x59, 0xd6, 0x2e, 0x92, 0x0a, 0x5b, 
            0x7f, 0x02, 0x33, 0x06, 0x3a, 0x82, 0x45, 0x52, 0x8b, 0xf4, 0xb7, 0xed, 0xca, 0x38, 0x5f, 0xcf }
    }
};

int check_result( uint8_t *result, uint8_t *expected, size_t size ) {
    int rc = 0;
    int j, k;

    for( j = 0; j < size; j++ ) {
        if( ( (uint8_t *) result)[ j ] != expected[ j ] ) {
            printf( " FAILED!\n" );
            printf( "   Result: " );
            for( k = 0; k < size; k += 4 ) {
                printf( "%02x%02x%02x%02x ",
                        result[ k ],
                        result[ k + 1 ],
                        result[ k + 2 ],
                        result[ k + 3 ] );
            }

            printf( "\n   Expect: " );
            for( k = 0; k < size; k += 4 ) {
                printf( "%02x%02x%02x%02x ",
                        expected[ k ],
                        expected[ k + 1 ],
                        expected[ k + 2 ],
                        expected[ k + 3 ] );
            }

            printf( "\n" );
            break;
        }
    }

    if( j == size ) {
        printf( " PASSED!\n" );
        rc = 1;
    }

    return rc;
}

void test_md5( void ) {
    uint8_t result[16];
    uint8_t buf[1000];
    int i, p;
    void *hash;

    hash = (uint8_t *) hash_md5_create();

    printf( "\nTesting MD5 hashing...\n" );

    for( i = 0; i < sizeof(testdata) / sizeof(struct _test_data); i++ ) {
        printf( "%s...", testdata[ i ].title );
        hash_md5_init( hash );
        hash_md5_update( hash, testdata[ i ].data, testdata[ i ].size );
        hash_md5_finalize( hash );
        hash_md5_get_value( hash, result, sizeof(result) );

        check_result( result, testdata[ i ].expected_md5, sizeof(testdata[ i ].expected_md5) );
    }

    p = (sizeof( testdata) / sizeof(struct _test_data)) - 1;

    printf( "%s (multiple updates)...", testdata[ p ].title );
    hash_md5_init( hash );
    for( i = 0; i < testdata[p].size; i += 100 ) {
        memcpy( buf, testdata[ p ].data + i, 100 );
        hash_md5_update( hash, buf, 100 );
    }

    hash_md5_finalize( hash );
    hash_md5_get_value( hash, result, sizeof(result) );

    check_result( result, testdata[ p ].expected_md5, sizeof(testdata[ p ].expected_md5) );

    hash_md5_destroy( hash );
}

void test_sha1( void ) {
    uint8_t result[20];
    uint8_t buf[1000];
    int i, p;
    void *hash;

    hash = (uint8_t *) hash_sha1_create();

    printf( "\nTesting SHA-1 hashing...\n" );
    for( i = 0; i < sizeof(testdata) / sizeof(struct _test_data); i++ ) {
        printf( "%s...", testdata[ i ].title );
        hash_sha1_init( hash );

        hash_sha1_update( hash, testdata[ i ].data, testdata[ i ].size );
        hash_sha1_finalize( hash );
        hash_sha1_get_value( hash, result, sizeof(result) );

        check_result( result, testdata[ i ].expected_sha1, sizeof(testdata[ i ].expected_sha1) );
    }

    p = (sizeof( testdata) / sizeof(struct _test_data)) - 1;

    printf( "%s (multiple updates)...", testdata[ p ].title );
    hash_sha1_init( hash );
    for( i = 0; i < testdata[p].size; i += 100 ) {
        memcpy( buf, testdata[ p ].data + i, 100 );
        hash_sha1_update( hash, buf, 100 );
    }

    hash_sha1_finalize( hash );
    hash_sha1_get_value( hash, result, sizeof(result) );

    check_result( result, testdata[ p ].expected_sha1, sizeof(testdata[ p ].expected_sha1) );

    hash_sha1_destroy( hash );
}

void test_sha2_256( void ) {
    uint8_t result[32];
    uint8_t buf[1000];
    int i, p;
    void *hash;

    hash = (uint8_t *) hash_sha2_256_create();

    printf( "\nTesting SHA-2 256-bits hashing...\n" );

    for( i = 0; i < sizeof(testdata) / sizeof(struct _test_data); i++ ) {
        printf( "%s...", testdata[ i ].title );
        hash_sha2_256_init( hash );

        hash_sha2_256_update( hash, testdata[ i ].data, testdata[ i ].size );
        hash_sha2_256_finalize( hash );
        hash_sha2_256_get_value( hash, result, sizeof(result) );

        check_result( result, testdata[ i ].expected_sha2_256, sizeof(testdata[ i ].expected_sha2_256) );
    }

    p = (sizeof( testdata) / sizeof(struct _test_data)) - 1;

    printf( "%s (multiple updates)...", testdata[ p ].title );
    hash_sha2_256_init( hash );
    for( i = 0; i < 1000; i += 100 ) {
        memcpy( buf, testdata[ p ].data + i, 100 );
        hash_sha2_256_update( hash, buf, 100 );
    }

    hash_sha2_256_finalize( hash );
    hash_sha2_256_get_value( hash, result, sizeof(result) );

    check_result( result, testdata[ p ].expected_sha2_256, sizeof(testdata[ p ].expected_sha2_256) );

    hash_sha2_256_destroy( hash );
}

void test_sha2_512( void ) {
    uint8_t result[64];
    uint8_t buf[1000];
    int i, p;
    void *hash;

    hash = (uint8_t *) hash_sha2_512_create();

    printf( "\nTesting SHA-2 512-bits hashing...\n" );

    for( i = 0; i < sizeof(testdata) / sizeof(struct _test_data); i++ ) {
        printf( "%s...", testdata[ i ].title );
        hash_sha2_512_init( hash );

        hash_sha2_512_update( hash, testdata[ i ].data, testdata[ i ].size );
        hash_sha2_512_finalize( hash );
        hash_sha2_512_get_value( hash, result, sizeof(result) );

        check_result( result, testdata[ i ].expected_sha2_512, sizeof(testdata[ i ].expected_sha2_512) );
    }

    p = (sizeof( testdata) / sizeof(struct _test_data)) - 1;

    printf( "%s (multiple updates)...", testdata[ p ].title );
    hash_sha2_512_init( hash );
    for( i = 0; i < 1000; i += 100 ) {
        memcpy( buf, testdata[ p ].data + i, 100 );
        hash_sha2_512_update( hash, buf, 100 );
    }

    hash_sha2_512_finalize( hash );
    hash_sha2_512_get_value( hash, result, sizeof(result) );

    check_result( result, testdata[ p ].expected_sha2_512, sizeof(testdata[ p ].expected_sha2_512) );

    hash_sha2_512_destroy( hash );
}

int main( int argc, char **argv ) {
    int mbIndex, i;
    printf( "libHash C tests \n" );

    mbIndex = (sizeof( testdata) / sizeof(struct _test_data)) - 2;
    testdata[ mbIndex ].data = malloc( 1000000 );
    memset( testdata[ mbIndex ].data, 'a', 1000000 );

    mbIndex = (sizeof( testdata) / sizeof(struct _test_data)) - 1;
    testdata[ mbIndex ].data = malloc( 1000 );
    for(i=0; i< testdata[mbIndex].size -1; i+=9) { 
        memcpy( testdata[ mbIndex ].data +i, "123456789", 10 );
    }
    ((uint8_t *) testdata[mbIndex].data)[1000] = '1';


    test_md5();
    test_sha1();
    test_sha2_256();
    test_sha2_512();

    mbIndex = (sizeof( testdata) / sizeof(struct _test_data)) - 2;
    free( testdata[ mbIndex ].data );
    mbIndex = (sizeof( testdata) / sizeof(struct _test_data)) - 1;
    free( testdata[ mbIndex ].data );
}

