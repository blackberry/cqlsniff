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
#include <time.h>
#include <sys/time.h>

#include "net.h"
#include "utils.h"
#include "stream.h"

StreamTracker::StreamTracker(size_t limit, int max_age, int long_query_usec, int hash, int hashmin, int include_sizes)
: num_queries(0), num_responses(0), num_rejected(0), num_duplicates(0), num_unknown_responses(0), num_expired(0),
  limit(limit), max_age(max_age), long_query_usec(long_query_usec), hash(hash), hashmin(hashmin),
  include_sizes(include_sizes), last_vacuum(0)
{
}

CQLFrame *StreamTracker::get(uint64_t stream_key) const
{
    auto it = stream_map.find(stream_key);
    if (it == stream_map.end())
        return 0;
    return (*it).second;
}

bool StreamTracker::addFrame(CQLFrame *cql)
{
    CQLFrame *request = get(cql->stream_key);
    if (cql->type == FrameType::Request) {
        if (request) {
            // A request already existed for this stream key, which means we
            // must have missed the response for it (or perhaps a duplicate TCP
            // packet).  Not much we can do now except to abandon it.
            num_duplicates++;
            logUncompletedRequest(request, RequestStatus::DuplicateStream);
            delete request;
        } else {
            // We're adding a new request to the map.  Check bounds.
            int vacuum_time = cql->timestamp.tv_sec - max_age;
            if (stream_map.size() >= limit) {
                // Our own version of GC thrashing. :)
                num_expired += vacuum(vacuum_time);
                if (stream_map.size() >= limit) {
                    logUncompletedRequest(cql, RequestStatus::Rejected);
                    num_rejected++;
                    return false;
                }
            } else if (last_vacuum <= vacuum_time) {
                // Run periodic vacuum.
                num_expired += vacuum(vacuum_time);
                last_vacuum = cql->timestamp.tv_sec;
            }
        }
        num_queries++;
        stream_map[cql->stream_key] = cql;
    } else {
        if (request) {
            // This CQL frame is a response which we've matched to a request.
            if (request->opcode == Opcode::Prepare) {
                // This is a response to a prepare request.
                prepared_queries[cql->query_id] = std::string(request->query, request->actual_query_len);
            } else {
                if (request->opcode == Opcode::Execute) {
                    auto it = prepared_queries.find(request->query_id);
                    if (it != prepared_queries.end()) {
                        request->query_len = request->actual_query_len = (*it).second.size();
                        strncpy(request->query, (*it).second.c_str(), request->query_len);
                    }
                }
            }
            logCompletedRequest(request, cql);
            num_responses++;
            remove(cql->stream_key);
            delete request;
        } else {
            num_unknown_responses++;
        }
        delete cql;
    }
    return true;
}

bool StreamTracker::shouldLog(const CQLFrame *request) const
{
    return (request->opcode == Opcode::Query || request->opcode == Opcode::Execute ||
            request->opcode == Opcode::Prepare);
}

void StreamTracker::log(const char *logline, const struct timeval *timestamp) const
{
    char timestr[64];
    struct tm *gm = gmtime(&timestamp->tv_sec);
    size_t pos = strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", gm);
    snprintf(&timestr[pos], sizeof(timestr) - pos, ".%-8ld", timestamp->tv_usec);
    printf("%s%s\n", timestr, logline);
}

void StreamTracker::logRequest(const CQLFrame *request, const CQLFrame *response, RequestStatus status) const
{
    if (!shouldLog(request))
        return;

    // 32K is (provably) more than enough to hold everything other than the query string.
    char logline[32768 + sizeof(CQLFrame::query)];
    int64_t duration_usec;
    size_t pos = 0;


    if (response) {
        duration_usec = (response->timestamp.tv_sec - request->timestamp.tv_sec) * 1000000 +
                        (response->timestamp.tv_usec - request->timestamp.tv_usec);
        if (duration_usec < long_query_usec)
            return;
    }

    logline[pos++] = '{';
    pos += request->serialize(&logline[pos], sizeof(logline) - pos, hash, hashmin, include_sizes);

    if (response) {
        if (response->opcode == Opcode::Result && response->num_rows != -1)
            // This is a result response and we know the number of rows.
            pos += snprintf(&logline[pos], sizeof(logline) - pos, ", \"nr\": %d", response->num_rows);
        pos += snprintf(&logline[pos], sizeof(logline) - pos, ", \"d\": %ld}", duration_usec);
        log(logline, &response->timestamp);
    } else {
        // No response available for this request.  Log it with the current
        // time and indicate result status (rs).
        struct timeval now;
        struct timezone tz;
        static const char *statuses[] = {"matched", "duplicate", "discarded", "expired"};
        gettimeofday(&now, &tz);
        pos += snprintf(&logline[pos], sizeof(logline) - pos, ", \"rs\": \"%s\"}", statuses[static_cast<int>(status)]);
        log(logline, &now);
    }
}


size_t StreamTracker::remove(uint64_t stream_key)
{
    return stream_map.erase(stream_key);
}


int StreamTracker::vacuum(time_t time)
{
    int n_removed = 0;
    for (auto it = stream_map.cbegin(); it != stream_map.cend();) {
        CQLFrame *cql = (*it).second;
        if (cql->timestamp.tv_sec < time) {
            it = stream_map.erase(it);
            logUncompletedRequest(cql, RequestStatus::Expired);
            delete cql;
            n_removed++;
        } else
            it++;
    }
    return n_removed;
}
