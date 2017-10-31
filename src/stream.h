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

#ifndef _STREAM_H_
#define _STREAM_H_

#include <unordered_map>
#include <string>

#include <inttypes.h>

#include "cqlframe.h"

enum class RequestStatus {
    // request was tracked through to response
    ResponseMatched,
    // the request was replaced by a new request on the same stream (e.g.
    // response was missed or duplicate packet)
    DuplicateStream,
    // request was rejected due to full map
    Rejected,
    // We did not see a response for this request within max_age
    Expired
};

class StreamTracker
{
    public:
        StreamTracker(size_t limit, int max_age, int long_query_usec, int hash, int hashmin, int include_sizes);
        CQLFrame *get(uint64_t stream_key) const;
        bool addFrame(CQLFrame *cql);
        size_t remove(uint64_t stream_key);
        size_t numStreams() const { return stream_map.size(); }
        size_t numPrepared() const { return prepared_queries.size(); }

        // Number of queries observed
        size_t num_queries;
        // Number of responses observed (that were matched up to a tracked query)
        size_t num_responses;
        // Number of requests with RequestStatus::Rejected
        size_t num_rejected;
        // Number of requests with RequestStatus::DuplicateStream
        size_t num_duplicates;
        // Number of responses that did not have a tracked request (perhaps
        // because we discarded it, or failed to parse it).
        size_t num_unknown_responses;
        // Number of requests with RequestStatus::Expired
        size_t num_expired;

    protected:
        bool shouldLog(const CQLFrame *request) const;
        void logRequest(const CQLFrame *request, const CQLFrame *response, RequestStatus status) const;
        void logCompletedRequest(const CQLFrame *request, const CQLFrame *response) const
            { logRequest(request, response, RequestStatus::ResponseMatched); }
        void logUncompletedRequest(const CQLFrame *request, RequestStatus status) const
            { logRequest(request, 0, status); }
        void log(const char *line, const struct timeval *timestamp) const;
        int vacuum(time_t before);

        // maps stream keys (identifiers that are unique across a cluster) to CQL requests.
        // Used to find the request for a given response.
        std::unordered_map<uint64_t, CQLFrame *> stream_map;
        // map prepared query ids to CQL query string
        std::unordered_map<std::string, std::string> prepared_queries;
        // allow no more than this many requests in the stream map
        size_t limit;
        // expire requests from map after waiting this long
        int max_age;
        // log queries that take longer than this
        int long_query_usec;
        // Whether we need to hash value data
        int hash;
        // Minimum data length before value will be hashed
        int hashmin;
        // Whether to include value sizes in JSON output
        int include_sizes;
        // timestamp that we last vacuumed the map
        time_t last_vacuum;
};
#endif
