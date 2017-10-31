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

#include <string.h>
#include <ctype.h>
#include <stdio.h>

#include "utils.h"


// Returns false if there exists a non-printable character in the string
// of size n, true otherwise.
bool isprint(const uint8_t *str, size_t n)
{
    for (; n > 0; n--, str++)
        if (!isprint(*str))
            return false;
    return true;
}

// Copies up to sn bytes from src to dst, escaping double quotes with backslashes in dst, and
// not exceeding dn bytes in dst.
//
// Returns the number of bytes written to dst (excluding the terminating null,
// which *is* written), unless a non-printable character was observed (defined
// as anything outside 0x20-0x7e) in which case -1 is returned.  If printable is
// true, then non-printable characters are hashed into a printable range.
int strncpy_escape(char *dst, size_t dn, const uint8_t *src, size_t sn, int *src_length_return, bool printable)
{
    const uint8_t *sp = src;
    char *dp = dst;
    while (dn && sn) {
        uint8_t sc = *sp++;
        sn--;
        if (printable)
            sc = sc % 76 + 0x2e;
        else if (sc < 0x20 || sc > 0x7e)
            return -1;
        if (sc == '"') {
            *dp++ = '\\';
            *dp++ = '"';
            dn -= 2;
        } else {
            *dp++ = (char)sc;
            dn--;
        }
    }
    *dp = 0;
    if (src_length_return)
        *src_length_return = sp - src;
    return dp - dst;
}

int hexlify(char *dst, size_t dn, const uint8_t *src, size_t sn, int *src_length_return)
{
    const uint8_t *sp = src;
    char *dp = dst;

    if (dn > 2) {
        dp[0] = '0';
        dp[1] = 'x';
        dp += 2;
        dn -= 2;
    }
    while (dn > 1 && sn) {
        uint8_t sc = *sp++;
        sn--;
        *dp++ = nibble_to_char(sc >> 4);
        *dp++ = nibble_to_char(sc & 0x0f);
        dn -= 2;
    }
    *dp = 0;
    if (src_length_return)
        *src_length_return = sp - src;
    return dp - dst;
}

int bytes_to_escaped_str(char *dst, size_t dn, const uint8_t *src, size_t sn, size_t truncate, int flags)
{
    int src_length,
        src_limit = truncate < sn ? truncate : sn;
    int pos = snprintf(dst, dn, "\"");
    if ((flags & CopyFlags::Hexlify) == 0) {
        int r = strncpy_escape(&dst[pos], dn - pos, src, src_limit, &src_length, flags & CopyFlags::Printable);
        if (r < 0)
            // If we're here, src contained non-printable characters, so must be hexlified.
            flags |= CopyFlags::Hexlify;
        else {
            pos += r;
        }
    }
    if (flags & CopyFlags::Hexlify) {
        pos += hexlify(&dst[pos], dn - pos, src, src_limit, &src_length);
    }
    if (flags & CopyFlags::Ellipsis && truncate < sn && dn - pos >= 4) {
        // We truncated src and there is still enough room in dst for the ellipsis (plus null terminator).
        strcpy(&dst[pos], "...");
        pos += 3;
    }
    pos += snprintf(&dst[pos], dn - pos, "\"");
    return pos;
}
