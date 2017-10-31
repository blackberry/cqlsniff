/**
 * Copyright 2017 BlackBerry, Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UTILS_H_
#define _UTILS_H_
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>

enum CopyFlags {
    Hexlify = 0x01,
    Ellipsis = 0x02,
    Printable = 0x04
};

bool isprint(const uint8_t *str, size_t n);
int strncpy_escape(char *dst, size_t dn, const uint8_t *src, size_t sn, int *src_length_return, bool printable);
int hexlify(char *dst, size_t dn, const uint8_t *src, size_t sn, int *src_length_return);
int bytes_to_escaped_str(char *dst, size_t dn, const uint8_t *src, size_t sn, size_t truncate, int flags);
inline int bytes_to_escaped_str(char *dst, size_t dn, const uint8_t *src, size_t sn, size_t truncate) {
    return bytes_to_escaped_str(dst, dn, src, sn, truncate, CopyFlags::Ellipsis);
}
inline char nibble_to_char(uint8_t nibble) {
    return nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);

}

inline void *memncpy(void *dst, size_t dn, const void *src, size_t sn) {
    size_t n = dn < sn ? dn : sn;
    return memcpy(dst, src, n);
}

template <class T> T max(T a, T b) {
    return a > b ? a : b;
}

template <class T> T min(T a, T b) {
    return a < b ? a : b;
}

#endif
