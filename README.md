# CQL Sniff

## About

Through packet sniffing the binary protocol port (9042/tcp by default), or by processing a previously captured pcap file, cqlsniff tracks and logs (to stdout currently) CQL queries.

Features include:
* Tracks queries and their responses, to provide a wire level view of response time
* Handles prepared statements (but must first observe the statement being prepared)
* Log CQL queries including the query values, consistency level, response time, and much more.
* Log format is JSON for easier offline analysis
* Query values can be optionally hashed to protect sensitive data
* Can filter logging to only log slow queries
* Can consume a pcap file (e.g. ``tcpdump -w cql.pcap port 9042``) for offline parsing
* Low memory, low CPU, low risk execution (passive by packet sniffing, process automatically niced and memory bounded)


Example output:

```
2016-02-26 21:39:50.698312  {"q": "SELECT * FROM accounts.messages WHERE user=? AND time>=1456502705889 LIMIT 100;", "cl": 6, "sz": 144, "nv": 1, "ip": "10.42.42.42", "t": 1456522790.695492, "op": 10, "v": ["arthurdent"], "vs": [10], "nr": 100, "d": 2820}
```

Where:
* *q*: the CQL query
* *cl*: the consistency level (values are defined in section 3 of the [CQL Binary Protocol specification](https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v3.spec))
* *sz*: total size of the CQL *request* frame
* *nv*: the total number of parameterized values that were included in the request
* *ip*: the IP address of the requesting client
* *t*: number of seconds since epoch the request came in
* *op*: the request opcode (values are defined in section 2.4 of the [CQL Binary Protocol specification](https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v3.spec))
* *v*: a list of parameterized values up to the configured limit (each value is truncated at 32 bytes if needed)
* *vs*: an array containing the size of each query parameter value (only when -z is specified)
* *nr*: number of rows returned in the response
* *d*: the duration in microseconds of the request (i.e. the elapsed time before the response was observed leaving the NIC)


Command line arguments:

```
Usage: cqlsniff [OPTION...] [pcap file]

  -e, --expire=SEC           Expire pending requests after this many seconds
                             (default: 12000)
  -f, --filter=FILTER        Capture filter (default: tcp and port 9042 and
                             greater 44)
  -h, --hash                 Hash values to obfuscate
  -i, --interface=DEVICE     Interface to capture on (default: auto detect)
  -l, --long=USEC            Only log queries that took longer than this many
                             microseconds (default: 0, i.e. log all)
  -m, --memory=MB            Restrict (virtual) memory to this many MB to
                             safeguard against OOM (default: 200)
  -n, --nice=LEVEL           Nice level for the process (default: 10)
  -p, --pending=COUNT        Max number of pending requests to track before
                             discarding (default: 2000)
  -s, --snaplen=BYTES        Snapshot this number of bytes from each packet
                             (default: 16384)
  -v, --values=COUNT         Maximum number of query values to output (default:
                             5)
  -x, --hashmin=LENGTH       Minimum data length in order for values to be
                             hashed (default: 2, implies --hash)
  -z, --sizes                Include sizes of all values in output
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```


## Building

You'll first need the dev package for libpcap and g++.  On Ubuntu:

```
sudo apt-get install libpcap-dev g++
```

g++ needs to be sufficiently new to support the early preview C++11 features.  What comes with Ubuntu 12.04 is late enough.  Then build:

```
make
```


## Limitations

These are the main limitations or known issues:
* When run from the Cassandra client side, the IP logged is unhelpfully that of the client, not the Cassandra server
* Logging is pretty limited.  Currently just outputs to stdout
* Protocol frames that span packet boundaries will be missed.  This is a result of the design, which operates on discrete packets.  Consequently, some requests or responses may be missed.
* CQL errors aren't logged properly yet.
* No support yet for IPv6.  (Wouldn't be too hard.)


## Contributing

Please read the [policy on contributions](http://blackberry.github.io/howToContribute.html).


## License

Apache 2.0 license
http://www.apache.org/licenses/LICENSE-2.0


## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
