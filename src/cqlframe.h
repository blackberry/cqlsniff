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

#ifndef _CQLFRAME_H_
#define _CQLFRAME_H_

#include <exception>

#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// Don't parse more than this many query values
#define MAX_QUERY_VALUES 150
#define MAX_VALUE_LENGTH 32

typedef struct {
    uint8_t version;
    uint8_t flags;
    uint8_t stream;
    uint8_t opcode;
    uint32_t length;
} cql_frame_header_v2;

typedef struct {
    uint8_t version;
    uint8_t flags;
    uint16_t stream;
    uint8_t opcode;
    uint32_t length;
} cql_frame_header_v3;


class CQLFrameError : public std::exception
{
};

class CQLFrameBufferTooShort : public CQLFrameError
{
    const char *what() const throw() {
        return "CQL frame buffer too short";
    }
};

class CQLFrameInvalid : public CQLFrameError
{
    const char *what() const throw() {
        return "Not a valid CQL Frame";
    }
};


enum class FrameType { Unknown, Request, Response };

enum Opcode {
    Error = 0x00,
    Startup = 0x01,
    Ready = 0x02,
    Authenticate = 0x03,
    Options = 0x05,
    Supported = 0x06,
    Query = 0x07,
    Result = 0x08,
    Prepare = 0x09,
    Execute = 0x0a,
    Register = 0x0b,
    Event = 0x0c,
    Batch = 0x0d,
    AuthChallenge = 0x0e,
    AuthResponse = 0x0f,
    AuthSuccess = 0x10
};

enum TypeCode {
    Custom = 0x0000,
    Ascii = 0x0001,
    Bigint = 0x0002,
    Blob = 0x0003,
    Boolean = 0x0004,
    Counter = 0x0005,
    Decimal = 0x0006,
    Double = 0x0007,
    Float = 0x0008,
    Int = 0x0009,
    Timestamp = 0x000b,
    Uuid = 0x000c,
    Varchar = 0x000d,
    Varint = 0x000e,
    Timeuuid = 0x000f,
    Inet = 0x0010,
    List = 0x0020,
    Map = 0x0021,
    Set = 0x0022,
    UDT = 0x0030,
    Tuple = 0x0031,
    Unknown = 0xffff
};

class CQLFrame
{
    public:
        static bool isFrame(const uint8_t *buf, size_t bufzs);
        CQLFrame(const struct timeval *ts,
                 const struct in_addr *src4, uint16_t srcport,
                 const struct in_addr *dst4, uint16_t dstport,
                 const uint8_t *buf, size_t bufsz);

        void parse(int max_query_values);
        int serialize(char *dst, size_t dstlen, int hash, int hashmin, int include_sizes) const;
        const char *streamInfo() const;


    protected:
        const void *advance(size_t sz);

        // Parse functions return the appropriate values, advance fp, and
        // throw CQLFrameBufferTooShort if buffer isn't big enough for requested value.
        uint8_t parseByte() { return *(uint8_t *)advance(sizeof(uint8_t)); }
        uint16_t parseShort() { return ntohs(*(uint16_t *)advance(sizeof(uint16_t))); }
        int32_t parseInt() { return ntohl(*(int32_t *)advance(sizeof(int32_t))); }
        uint8_t *parseBytes(int32_t *size_return);
        uint8_t *parseShortBytes(uint16_t *size_return);
        uint8_t *parseString(uint16_t *size_return) { return parseShortBytes(size_return); }
        uint8_t *parseLongString(int32_t *size_return) { return parseBytes(size_return); }
        uint16_t parseType();

        void parseResult();
        void parseQueryValues(int max_query_values);

        size_t scramble(uint8_t *dst, const uint8_t *src, size_t dstlen, size_t srclen) const;
        size_t serializeValue(char *dst, size_t dn, const uint8_t *src, size_t sn, size_t truncate, bool hash) const;

    public:
        struct sockaddr_storage src, dst;

        // CQL frame header
        uint8_t version, flags;
        Opcode opcode;
        uint16_t stream;
        int32_t header_len, frame_len;
        FrameType type;

        // Query opcode variables
        uint8_t query_flags;
        // consistency level for query (-1 means unknown, i.e. packet too short)
        int consistency;
        // number of CQL values (-1 means unknown)
        int n_values;

        // Length of the query according to the protocol
        int32_t query_len;
        // Actual amount of data that was copied to the query string.
        int32_t actual_query_len;
        // As much of the CQL query as we saw in the packet.  This can be less
        // than query_len.
        char query[32768];
        // For prepared queries (or responses) this is the query id.
        // XXX: 256 is not a max per the spec.  It is 16 empirically.
        // This is a possible bug.
        char query_id[256];

        // number of rows if this is a result response.  (-1 means unknown)
        int32_t num_rows;

        // Timestamp from libpcap
        struct timeval timestamp;
        // a unique 64 bit value representing this stream (combination of client IP,
        // port, and stream number)
        uint64_t stream_key;

    protected:
        const uint8_t *buf, // pointer to original frame buffer
                      *fp,  // pointer to the current position in the frame buffer
                      *bufend; // pointer to end of buffer (for bounds checking)
        size_t bufsz;
        uint8_t values[MAX_QUERY_VALUES][MAX_VALUE_LENGTH];
        int32_t value_sizes[MAX_QUERY_VALUES];

        // Number of CQL values actually parsed (based on user limits)
        int n_parsed_values;
};
#endif
