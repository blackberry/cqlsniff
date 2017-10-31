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

#include <iostream>

#include <argp.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>
#include <pwd.h>
#include <pcap.h>

#include "net.h"
#include "utils.h"
#include "cqlframe.h"
#include "stream.h"

const char *argp_program_version = "cqlsniff 1.2";
const char *argp_program_bug_address = "https://github.com/blackberry/cqlsniff/issues";

struct arguments {
    char interface[IFNAMSIZ];
    char filter[512];
    char file[PATH_MAX];
    int snaplen;
    int memory_limit_mb;
    int nice;
    int max_pending;
    int long_query_usec;
    int expire_sec;
    int max_query_values;
    int hash;
    int hashmin;
    int sizes;
    char user[LOGIN_NAME_MAX];
};

struct pcapdata {
    pcap_t *pcap;
    StreamTracker *stream_tracker;
    // total number of packets received from pcap
    size_t num_packets_processed;
    // number of packets that failed to parse
    size_t num_parse_errors;
    struct arguments *args;
};

static struct argp_option options[] = {
    {"interface", 'i', "DEVICE", 0, "Interface to capture on (default: auto detect)"},
    {"filter", 'f', "FILTER", 0, "Capture filter (default: tcp and port 9042 and greater 44)"},
    {"snaplen", 's', "BYTES", 0, "Snapshot this number of bytes from each packet (default: 16384)"},
    {"memory", 'm', "MB", 0, "Restrict (virtual) memory to this many MB to safeguard against OOM (default: 200)"},
    {"nice", 'n', "LEVEL", 0, "Nice level for the process (default: 10)"},
    {"pending", 'p', "COUNT", 0, "Max number of pending requests to track before discarding (default: 2000)"},
    {"long", 'l', "USEC", 0, "Only log queries that took longer than this many microseconds (default: 0, i.e. log all)"},
    {"expire", 'e', "SEC", 0, "Expire pending requests after this many seconds (default: 12000)"},
    {"values", 'v', "COUNT", 0, "Maximum number of query values to output (default: 5)"},
    {"hash", 'h', 0, 0, "Hash values to obfuscate"},
    {"hashmin", 'x', "LENGTH", 0, "Minimum data length in order for values to be hashed (default: 3, implies --hash)"},
    {"sizes", 'z', 0, 0, "Include sizes of all values in output"},
    {"drop", 'D', "USER", 0, "Drop privileges and change the user id to the given user"},
    {0}
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
    struct arguments *args = (struct arguments *)state->input;
    switch (key) {
        case 'i':
            strncpy(args->interface, arg, sizeof(args->interface));
            break;

        case 'f':
            strncpy(args->filter, arg, sizeof(args->filter));
            break;

        case 's':
            args->snaplen = atoi(arg);
            break;

        case 'm':
            args->memory_limit_mb = atoi(arg);
            break;

        case 'n':
            args->nice = atoi(arg);
            break;

        case 'p':
            args->max_pending = atoi(arg);
            break;

        case 'l':
            args->long_query_usec = atoi(arg);
            break;

        case 'e':
            args->expire_sec = atoi(arg);
            break;

        case 'v':
            args->max_query_values = atoi(arg);
            break;

        case 'h':
            args->hash = 1;
            break;

        case 'x':
            args->hash = 1;
            args->hashmin = atoi(arg);
            break;

        case 'z':
            args->sizes = 1;
            break;

        case 'D':
            strncpy(args->user, arg, sizeof(args->user));
            break;

        case ARGP_KEY_ARG:
            strncpy(args->file, arg, sizeof(args->file));
            break;
    }
    return 0;
}

static char args_doc[] = "[pcap file]";
static struct argp argp = {options, parse_opt, args_doc, 0};


static void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static time_t last_status_time = 0;
    struct pcapdata *userdata = (struct pcapdata *)args;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    uint8_t *payload;

    int iphdr_size;
    int tcphdr_size;
    size_t payload_size, offset = 0;

    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    iphdr_size = IP_HL(ip) * 4;
    if (iphdr_size < 20)
        // Invalid IP header
        return;

    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + iphdr_size);
    tcphdr_size = TH_OFF(tcp) * 4;
    if (tcphdr_size < 20)
        // Invalid TCP header length
        return;

    // TCP payload starts just after TCP header
    payload = (u_char *)(packet + SIZE_ETHERNET + iphdr_size + tcphdr_size);

    // Start with the segment size advertised by the TCP header ...
    payload_size = ntohs(ip->ip_len) - (iphdr_size + tcphdr_size);

    // ... and if necessary clamp it to the packet capture length.
    if (payload_size + SIZE_ETHERNET + iphdr_size + tcphdr_size > header->caplen)
        payload_size = header->caplen - (SIZE_ETHERNET + iphdr_size + tcphdr_size);

    while (offset < payload_size) {
        // Before proceeding, do a cheap test to see if this is a likely CQL frame.
        if (!CQLFrame::isFrame(payload + offset, payload_size - offset)) {
            // It's not, so we need to discard the whole packet.
            userdata->num_parse_errors++;
            break;
        }

        CQLFrame *cql = new CQLFrame(&header->ts, &ip->ip_src, tcp->th_sport, &ip->ip_dst, tcp->th_dport, payload + offset, payload_size - offset);
        try {
            cql->parse(userdata->args->max_query_values);
        } catch (CQLFrameError &ex) {
            // The quick test showed this could be a CQL frame, but a more in depth parsing
            // showed this to be a false positive.
            userdata->num_parse_errors++;
            delete cql;
            break;
        }

        // Frame is valid.  Increment buffer offset based on size of CQL frame.
        offset += cql->header_len + cql->frame_len;

        if (!userdata->stream_tracker->addFrame(cql)) {
            // Tracker rejected the frame (map full).  Unlike above, because
            // this is confirmed to be a valid CQL frame, we don't break the
            // loop, but continue in case there are response packets later in
            // the buffer.
            delete cql;
        }
    }

    userdata->num_packets_processed++;
    if (header->ts.tv_sec - last_status_time >= 10) {
        struct pcap_stat ps;
        pcap_stats(userdata->pcap, &ps);
        fprintf(stderr, "status: bad=%lu/%lu discard=%lu dupe=%lu exp=%ld drop=%d:%d prepared=%lu streams=%lu\n",
                userdata->num_parse_errors, userdata->num_packets_processed,
                userdata->stream_tracker->num_rejected,
                userdata->stream_tracker->num_duplicates,
                userdata->stream_tracker->num_expired,
                ps.ps_drop, ps.ps_ifdrop,
                userdata->stream_tracker->numPrepared(),
                userdata->stream_tracker->numStreams());
        last_status_time = header->ts.tv_sec;
    }
}

int main(int argc, char **argv)
{
    struct arguments args = {
        // device name
        "",
        // filter
        "tcp and port 9042 and greater 44",
        // pcap file (empty string means do live capture)
        "",
        // snaplen
        16384,
        // memory_limit_mb
        200,
        // nice level
        10,
        // max_pending
        2000,
        // long_query_usec
        0,
        // expire_sec
        12,
        // max_query_values
        5,
        // hash
        0,
        // hashmin
        3,
        // sizes
        0,
        // setuid to this user
        ""
    };
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    struct pcapdata userdata;
    struct bpf_program fp;

    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (args.memory_limit_mb > 0) {
        // Cap memory
        struct rlimit rlim;
        fprintf(stderr, "setting memory ulimit to %d MB\n", args.memory_limit_mb);
        rlim.rlim_cur = rlim.rlim_max = args.memory_limit_mb * 1024 * 1024;
        if (setrlimit(RLIMIT_AS, &rlim) < 0) {
            fprintf(stderr, "failed setting memory limit: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    if (nice(args.nice) < 0) {
        fprintf(stderr, "failed nicing process: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (args.max_query_values > MAX_QUERY_VALUES) {
        fprintf(stderr, "given number of query values (%d) exceeds hardcoded maximum (%d)\n",
                args.max_query_values, MAX_QUERY_VALUES);
        exit(EXIT_FAILURE);
    }

    if (*args.file) {
        // Read a saved pcap file
        pcap = pcap_open_offline(args.file, errbuf);
        if (!pcap) {
            fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }

    }
    else {
        char *dev = args.interface;
        if (!*dev) {
            dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                exit(EXIT_FAILURE);
            }
        }

        // Can't use pcap_open_live() if we want to set buffer size.
        pcap = pcap_create(dev, errbuf);
        if (!pcap) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }
        if (pcap_set_snaplen(pcap, args.snaplen) < 0 ||
            pcap_set_timeout(pcap, 1000) < 0 ||
            pcap_set_buffer_size(pcap, 1024*1024*32) < 0 ||
            pcap_activate(pcap) < 0) {
            fprintf(stderr, "failed to configure and activate device: %s\n", pcap_geterr(pcap));
            exit(EXIT_FAILURE);
        }
        if (pcap_datalink(pcap) != DLT_EN10MB) {
            fprintf(stderr, "%s is not an Ethernet device\n", dev);
            exit(EXIT_FAILURE);
        }
    }

    if (pcap_compile(pcap, &fp, args.filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", args.filter, pcap_geterr(pcap));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", args.filter, pcap_geterr(pcap));
        exit(EXIT_FAILURE);
    }

    if (*args.user) {
        struct passwd *p = getpwnam(args.user);
        if (!p) {
            fprintf(stderr, "Unknown user: %s\n", args.user);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "Changing uid to %s (%d:%d)\n", args.user, p->pw_uid, p->pw_gid);
        if (setgid(p->pw_gid) != 0 || setuid(p->pw_uid) != 0) {
            perror("failed to drop privileges");
            exit(EXIT_FAILURE);
        }
    }

    userdata.stream_tracker = new StreamTracker(args.max_pending, args.expire_sec, args.long_query_usec,
                                                args.hash, args.hashmin, args.sizes);
    userdata.pcap = pcap;
    userdata.args = &args;

    pcap_loop(pcap, -1, handle_packet, (u_char *)&userdata);

    pcap_freecode(&fp);
    pcap_close(pcap);

    return 0;
}
