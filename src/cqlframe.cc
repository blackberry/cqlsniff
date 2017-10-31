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

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <endian.h>

#include "cqlframe.h"
#include "utils.h"
#include "cityhash/city.h"


bool CQLFrame::isFrame(const uint8_t *buf, size_t bufsz)
{
    if (bufsz < sizeof(cql_frame_header_v2))
        // There isn't enough in the buffer
        return false;

    uint8_t version = *buf & ~0x80;
    uint8_t flags = *++buf;
    return (version == 0x01 || version == 0x02 || version == 0x03) && flags <= 3;
}


CQLFrame::CQLFrame(const struct timeval *ts,
                   const struct in_addr *src4, uint16_t srcport,
                   const struct in_addr *dst4, uint16_t dstport,
                   const uint8_t *buf, size_t bufsz)
: type(FrameType::Unknown), consistency(-1), n_values(-1), actual_query_len(0), num_rows(-1),
  buf(buf), fp(buf), bufsz(bufsz), n_parsed_values(0)
{
    struct sockaddr_in *src_in = (struct sockaddr_in *)&src;
    struct sockaddr_in *dst_in = (struct sockaddr_in *)&dst;
    src_in->sin_family = AF_INET;
    src_in->sin_port = srcport;
    memcpy(&src_in->sin_addr, src4, sizeof(struct in_addr));

    dst_in->sin_family = AF_INET;
    dst_in->sin_port = dstport;
    memcpy(&dst_in->sin_addr, dst4, sizeof(struct in_addr));

    timestamp.tv_sec = ts->tv_sec;
    timestamp.tv_usec = ts->tv_usec;
    bufend = buf + bufsz;
}

const void *CQLFrame::advance(size_t sz)
{
    const void *ptr = fp;
    if (fp + sz > bufend)
        throw CQLFrameBufferTooShort();

    fp += sz;

    // Apart from the obvious test above to make sure we don't extend beyond
    // the range of the packet buffer, here we also make sure the new pointer
    // isn't ahead of the buffer.  This is a naive way to detect an overflow
    // in the above addition.  Note that it's not foolproof: we could have
    // wrapped back around into the boundary of the packet buffer.  But that is
    // improbable, and will just result in parse errors anyway (which is the
    // correct behaviour).  As long as we have avoided segv.
    //
    // Ideally we would use GCC's builtins for overflow detection but these
    // aren't available before GCC 5.
    if (fp < buf) {
        fp = (const uint8_t *)ptr;
        throw CQLFrameBufferTooShort();
    }

    return ptr;
}

uint8_t *CQLFrame::parseBytes(int32_t *size_return)
{
    int32_t size = parseInt();
    if (size_return)
        *size_return = size;
    return size >= 0 ? (uint8_t *)advance(size) : 0;
}

uint8_t *CQLFrame::parseShortBytes(uint16_t *size_return)
{
    uint16_t size = parseShort();
    if (size_return)
        *size_return = size;
    return (uint8_t *)advance(size);
}

// Parses and returns the type.
uint16_t CQLFrame::parseType()
{
    uint16_t col_type = parseShort();
    if (col_type == TypeCode::Custom) {
        // custom, string follows.
        parseString(0);
    } else if (col_type == TypeCode::Map) {
        // Map type has two options as key/value
        parseType(); // key
        parseType(); // value
    } else if (col_type == TypeCode::List || TypeCode::Set) {
        // list and set types have subtypes as option value
        parseType();
    }
    return col_type;
}

void CQLFrame::parse(int max_query_values)
{
    version = *fp;
    try {
        if (version == 0x01 || version == 0x81 || version == 0x02 || version == 0x82) {
            header_len = 8;
            cql_frame_header_v2 *h2 = (cql_frame_header_v2 *)advance(header_len);
            flags = h2->flags;
            stream = h2->stream;
            opcode = static_cast<Opcode>(h2->opcode);
            frame_len = ntohl(h2->length);
        } else if (version == 0x03 || version == 0x83) {
            // v3 header is packed on the wire, so we can't read it directly into our
            // neatly aligned in-memory structure.
            fp++;
            header_len = 9;
            flags = parseByte();
            stream = parseShort();
            opcode = static_cast<Opcode>(parseByte());
            frame_len = parseInt();
        } else {
            // Unsupported version or not actually a CQL frame.
            throw CQLFrameInvalid();
        }
    } catch (CQLFrameBufferTooShort &ex) {
        throw CQLFrameInvalid();
    }
    type = version & 0x80 ? FrameType::Response : FrameType::Request;

    // Sanity check flags: based on the v3 spec, only 0x01 and 0x02 are used,
    // so reject any packet with other bits set.  Also we don't support
    // compression (0x01) yet, and any opcode over 0x10 is invalid (as of v3)
    // so reject those as well.  The spec also restricts frames to less than
    // 256MB, so reject anything larger.
    if (flags & 0x01 || flags > 3 || opcode > 0x10 || frame_len < 0 || frame_len > 256*1024*1024)
        throw CQLFrameInvalid();

    // Build a cluster-unique "stream key" value for this stream, which is based on the
    // client's IP address and port, as well as the stream number as part of the C*
    // binary protocol.
    if (src.ss_family == AF_INET) {
        struct sockaddr_in *client = (struct sockaddr_in *)(type == FrameType::Request ?  &src : &dst);
        uint64_t ip = *(uint32_t *)&client->sin_addr;
        stream_key = (ip << 32) + (client->sin_port << 16) + stream;
    }

    if (opcode == Opcode::Query || opcode == Opcode::Prepare) {
        query_len = parseInt();
        // Just keep track of the position of the CQL query statement.  Don't
        // actually copy it until after we have a chance to do additional
        // validation on data following the query.
        const uint8_t *fp_cql = 0;
        try {
            fp_cql = (uint8_t *)advance(query_len);
            actual_query_len = query_len;
            if (opcode == Opcode::Query)
                parseQueryValues(max_query_values);
        } catch (CQLFrameBufferTooShort &ex) {
            // Query is truncated.  Grab what we can.  (parseQueryValues() will not throw
            // CQLFrameBufferTooShort so we know it was the above advance() that failed.
            actual_query_len = bufend - fp;
            advance(actual_query_len);
        }
        if (actual_query_len == 0 || fp_cql == 0)
            // But if we don't have *any* of the CQL query, assume this is not a
            // valid frame.
            throw CQLFrameInvalid();
        else
            memncpy(query, sizeof(query), fp_cql, actual_query_len);
    } else if (opcode == Opcode::Execute) {
        // Parse the prepared statement id.
        uint16_t sz;
        uint8_t *ptr = parseShortBytes(&sz);
        memncpy(query_id, sizeof(query_id), ptr, sz);

        parseQueryValues(max_query_values);

        // Create a dummy query string based on the prepared statement id.  Hopefully
        // the StreamTracker will have been able to observe the preparation of this
        // query id, but if not, then serializing will write this dummy string instead.
        char query_id_str[512];
        hexlify(query_id_str, sizeof(query_id_str), (uint8_t *)query_id, sz, 0);
        sprintf(query, "<prepared statement %s>", query_id_str);
        actual_query_len = query_len = strlen(query);
    } else if (opcode == Opcode::Result) {
        try {
            parseResult();
        } catch (CQLFrameBufferTooShort &ex) {
        }
    } else if (opcode == Opcode::Error) {
        int32_t code = parseInt();
        // Unfortunately the error opcode is 0x00 which means it's ripe for
        // false positives.  Even having made it this far through several
        // sanity checks, any frame reporting an error code greater than
        // the highest code in the v3 spec is treated as invalid.
        if (code > 0x2500)
            throw CQLFrameInvalid();
        uint16_t sz;
        uint8_t *msg = parseString(&sz);
        *(msg + sz) = 0;
        fprintf(stderr, "TODO: handle error opcode: 0x%x %s\n", code, msg);
    }
}


void CQLFrame::parseQueryValues(int max_query_values)
{
    // Consistency level is immediately following the query string.  Very large queries
    // may span multiple packets, so we may not have visibility into it.  But if we do,
    // validate it.
    try {
        consistency = parseShort();
        // v2 of the protocol defines LOCAL_ONE, the last of the supported CLs,
        // as 0x10.  v3 redefines this as 0x0a.  So as a quick sanity test,
        // anything above 0x10 is invalid.
        if (consistency >= 0x10)
            throw CQLFrameInvalid();

        query_flags = parseByte();
        if (query_flags & 0x01) {
            n_values = parseShort();
            for (int i = 0; i < n_values && i < max_query_values && i < MAX_QUERY_VALUES; i++, n_parsed_values++) {
                try {
                    if (query_flags & 0x40)
                        // Column name is present, parse and throwaway.
                        parseString(0);
                    uint8_t *value = parseBytes(&value_sizes[i]);
                    // Bytes fields can have values < 0 in which case null is
                    // returned by parseBytes().
                    if (value && value_sizes[i] > 0)
                        memncpy(values[i], sizeof(values[i]), value, value_sizes[i]);
                } catch (CQLFrameBufferTooShort &ex) {
                    value_sizes[i] = 0;
                    throw;
                }
            }
        } else {
            // Query flags indicates no values follow.
            n_values = 0;
        }

    } catch (CQLFrameBufferTooShort &ex) {
        // Allow partial frames.
    }
}

void CQLFrame::parseResult()
{
    int32_t kind = parseInt();
    if (kind == 0x02) {
        // Result contains rows.
        int32_t result_flags = parseInt();
        int32_t n_columns = parseInt();
        if (result_flags & 0x02) {
            // Paging state
            parseBytes(0);
        }
        if ((result_flags & 0x04) == 0) {
            // no_metadata flag is not set, so we have more parsing to do.
            if (result_flags & 0x01) {
                // global table spec
                parseString(0); // keyspace name
                parseString(0); // table name
            }
            for (int i = 0; i < n_columns; i++) {
                if ((result_flags & 0x01) == 0) {
                    // no global table spec.
                    parseString(0); // keyspace name
                    parseString(0); // table name
                }
                parseString(0); // column name
                parseType(); // column type
            }
        }
        // All this parsing, just to finally make our way to the value
        // we are actually interested in: number of rows.
        num_rows = parseInt();
    } else if (kind == 0x04) {
        uint16_t sz;
        uint8_t *ptr = parseShortBytes(&sz);
        memncpy(query_id, sizeof(query_id), ptr, sz);
    }
}


int CQLFrame::serialize(char *str, size_t size, int hash, int hashmin, int include_sizes) const
{
    char ip[NI_MAXHOST];
    size_t pos = 0;

    getnameinfo((struct sockaddr *)&src, sizeof(src), ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);

    pos += snprintf(&str[pos], size - pos, "\"q\": ");
    if (actual_query_len > 0) {
        pos += bytes_to_escaped_str(&str[pos], size - pos, (const uint8_t *)query, query_len, actual_query_len);
        if (actual_query_len < query_len)
            // Print ellipsis in query to indicate if it was truncated
            pos += snprintf(&str[pos], size - pos, "...");
    }
    pos += snprintf(&str[pos], size - pos,
                    ", \"cl\": %d, \"sz\": %d, \"nv\": %d, \"ip\": \"%s\", \"t\": %lu.%lu",
                    consistency, frame_len, n_values, ip, timestamp.tv_sec, timestamp.tv_usec);
    #if 1
        pos += snprintf(&str[pos], size - pos, ", \"op\": %d", opcode);
    #endif
    if (n_values > 0) {
        pos += snprintf(&str[pos], size - pos, ", \"v\": [");
        for (int i = 0; i < n_parsed_values; i++) {
            if (i > 0)
                pos += snprintf(&str[pos], size - pos, ", ");
            pos += serializeValue(&str[pos], size - pos, values[i], value_sizes[i], MAX_VALUE_LENGTH,
                                  hash && value_sizes[i] >= hashmin);
        }
        pos += snprintf(&str[pos], size - pos, "]");

        if (include_sizes) {
            pos += snprintf(&str[pos], size - pos, ", \"vs\": [");
            for (int i = 0; i < n_parsed_values; i++) {
                if (i > 0)
                    pos += snprintf(&str[pos], size - pos, ", ");
                pos += snprintf(&str[pos], size - pos, "%d", value_sizes[i]);
            }
            pos += snprintf(&str[pos], size - pos, "]");
        }
    }
    return pos;
}

// Serialize a single CQL value to a string.
size_t CQLFrame::serializeValue(char *dst, size_t dn, const uint8_t *src, size_t sn, size_t truncate, bool hash) const
{
    if (sn == 0)
        return snprintf(dst, dn, "null");

    uint8_t hashed[MAX_VALUE_LENGTH];
    int flags = CopyFlags::Ellipsis;
    // Use a heuristic to determine if this is likely to be a numeric field.  Any
    // byte sequence 2, 4 or 8 characters long that has any non-printable character
    // is considered numeric.
    bool numeric = (sn == 2 || sn == 4 || sn == 8) && !isprint(src, sn);
    if (hash) {
        sn = scramble(hashed, src, dn, min<int>(sn, MAX_VALUE_LENGTH));
        src = (uint8_t *)&hashed;
        flags |= CopyFlags::Printable;
    }
    if (numeric) {
        switch(sn) {
            case 2:
                uint16_t i2;
                memcpy(&i2, src, sizeof(i2));
                return snprintf(dst, dn, "%hu", htobe16(i2));
            case 4:
                int32_t i4;
                memcpy(&i4, src, sizeof(i4));
                return snprintf(dst, dn, "%d", htobe32(i4));
            case 8:
                int64_t i8;
                memcpy(&i8, src, sizeof(i8));
                return snprintf(dst, dn, "%ld", htobe64(i8));
        }
    }
    return bytes_to_escaped_str(dst, dn, src, sn, truncate, flags);
}

// Hashes the given data, ensuring the output size is equal to input size.
size_t CQLFrame::scramble(uint8_t *dst, const uint8_t *src, size_t dstlen, size_t srclen) const
{
    size_t pos = 0,
           size = srclen > dstlen ? dstlen : srclen;
    while (pos < size) {
        int chunklen = size - pos > sizeof(uint64_t) ? sizeof(uint64_t) : size - pos;
        uint64_t hash = CityHash64((const char *)&src[pos], chunklen);
        memcpy(&dst[pos], &hash, chunklen);
        pos += sizeof(uint64_t);
    }
    return size;
}

const char *CQLFrame::streamInfo() const
{
    static char info[128];
    if (src.ss_family == AF_INET) {
        char ip[NI_MAXHOST];
        struct sockaddr_in *client = (struct sockaddr_in *)(type == FrameType::Request ?  &src : &dst);
        getnameinfo((struct sockaddr *)client, sizeof(struct sockaddr_in), ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
        snprintf(info, sizeof(info), "%s,%d,%d", ip, ntohs(client->sin_port), stream);
    }
    return info;
}
