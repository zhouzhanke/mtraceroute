# mtraceroute (alpha)

Multipath traceroute (`mtraceroute`) is based on and implements similar functionality to [Paris traceroute](https://paris-traceroute.net). It keeps the flow identifier of probe packets fixed to avoid triggering traffic load balancing in Internet routes whenever possible. Moreover, `mtraceroute` implements the [Multipath Detection Algorithm](https://paris-traceroute.net/publications), which identifies routers that perform load balancing on the route from a source to a destination. `mtraceroute` systematically varies probe packets’ headers to classify load balancing behavior. 

## Download and build
```
% git clone https://github.com/TopologyMapping/mtraceroute
% autoreconf --install
% ./configure
% make
```

## Dependencies

Linux, gcc, libpcap and root access

## Usage
```
mtraceroute ADDRESS [-c command] [-w wait] [-z send-wait]

    -c command: traceroute|ping|mda, default: traceroute
    -r number of retries: default: 2
    -w seconds to wait for answer: default: 1
    -z milliseconds to wait between sends: default: 20
            
    MDA: -c mda [-a confidence] [-f flow-id] [-t max-ttl]

        -a confidence level in %: 90|95|99, default: 95
        -f what flow identifier to use, some values depends on
           the type of the address
           IPv4: icmp-chk, icmp-dst, udp-sport, udp-dst, tcp-sport, tcp-dst
                 Default: udp-sport
           IPv6: icmp-chk, icmp-dst, icmp-fl, icmp-tc, udp-sport, udp-dst,
                 udp-fl, udp-tc, tcp-sport, tcp-dst, tcp-fl, tcp-tc
                 Default: udp-sport
        -t max number of hops to probe: default: 30

    TRACEROUTE: -c traceroute [-t max-ttl] [-m method] [-p probes-at-once]

        -t max number of hops to probe: default: 30
        -m method of probing: icmp|udp|tcp, default: icmp
        -p number of probes to send at once: default: 3

    PING: -c ping [-n send-probes]

        -n number of probes to send: default: 5
```

## Contributing

Please check https://github.com/TopologyMapping/mtraceroute/issues

# Notice
mt.c is 程序入口
目前项目计划中有三大功能，分别是

    1 - ping
    2 - MDA
    3 - paris-traceroute

目前主要问题

    1 - 命名混乱，不要以常人的理解去阅读代码，会造成误导效果。
    2 - 作者是git初学者，不会分支控制，也没有tag，所以代码中出现没有用（或者目前没有用,但是未来可能有用）的内容是很正常的。
    3 - paris-traceroute问题
        3.1 - 同时探测多个跳数，但不对回收过程进行控制，导致回收是无序的。
        3.2 - 输出时因为回收过程是无序的，所以输出是无序的，并且如果提前找到最后一跳，就会忽略部分结果。
        3.3 - 时间计算部分是在sleep后所以结构上是错误的，但是因为sleep永远不会触发，所以结果是正确的。