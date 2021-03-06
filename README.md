most_connected_ip
=================

## Status

- Maintained. Works on Fedora 28 on 2018-10-28.

## What is it

This is a Perl script to display the <em>currently active TCP connections</em> and their TCP
state on the local machine, grouped by endpoint (IP:port), with any remote IP address resolved 
to its reverse DNS name, if possible. 

This is done by scanning the `netstat(8)` output, the script is thus meant for a Unix.

For example, run it using:

    perl most_connected_ip.pl --loop=5 --dnsnamelen=5

Output will be produced every 5 seconds, with the column showing the result of reverse-lookup
DNS 80 characters wide. 

The following can be passed:

    --debug         To activate debugging output.
    --nodns         To disable reverse DNS lookup; just IP addresses will be printed.
    --notiming      Do not insert time taken for DNS lookups in output.
                    (note that timing is printed only on lookup; if there is a cache
                    hit on the program cache, no timing information will be printed in any case)
    --debugdns      Print time taken for DNS lookup to STDERR; useful when debugging DNS problems.
                    (you may also want to wield this: 'tcpdump -i lo udp port 53')
    --dnsnamelen=N  Size of column holding the DNS lookup result (default 50; at least 30).
    --loop[=N]      The program will loop every N seconds, forever, instead of running once only.
                    (N can be missing (default is 1) or else 1..3600)

## Problems

Short-lived connections that a created and disappear before they can appear in the next `netstat` listing are invisible.
For that, only something based on `tcpdump(8)` helps.

The program may appear slow if `/etc/resolv.conf` does not explicitly say `nameserver 127.0.0.1`, causing
DNS resolution to issue a IPv6 request which times out.

## Similar programs

   - [tcptrack](http://linux.die.net/man/1/tcptrack) - That's basically it. No longer available at its old Christmas Island address, but you can just `yum install tcptrack`.
   - [nnetstat.pl](http://www.muenster.de/~alnep/linux/Nnetstat/) - Perl/Gtk version of netstat.
   - [Wireshark](http://www.wireshark.org/) - Wireshark (ex Ethereal), which is the dog's bollocks
   - For Microsoft Windows, there is [tcpview](http://technet.microsoft.com/en-us/sysinternals/bb897437.aspx)
   - [nethogs](https://github.com/raboof/nethogs#readme) - NetHogs is a small 'net top' tool, grouping bandwidth by process.

## Sample output

Below is a sample output that shows two "inbound" TCP connections to ports 777 and 443 (one line for
each), three "outbound" TCP connections to some remote machines on ports 777 and 25 (the first two
connections on one line as they go to the same address and port and the third connection on a separate
line), as well as a bunch of random TCP connections going over the loopback interface. 

Also shown are the TCP connections' states and the reverse-resolved name of the remote IP addresses.

Note the "10 duplicates" indication shown in the "looping connections" header. Sometimes there are connections
over the loopback interface for which `netstat` prints two lines, and so the script ignores one of them. 10
lines have been ignored in this case.


    Distant inbound connections: 2
        85.93.216.17:777               <-- 78.141.139.10       :    1        ip-78-141-139-10.dyn.luxdsl.pt.lu     1 x ESTABLISHED
        80.90.47.155:443               <-- 78.141.139.10       :    1        ip-78-141-139-10.dyn.luxdsl.pt.lu     1 x ESTABLISHED
    Distant outbound connections: 3
        80.90.63.61                    --> 80.90.63.48:25      :    2        smtp.m-plify.net                      2 x TIME_WAIT
        85.93.216.17                   --> 85.93.216.18:777    :    1        maya.m-plify.net                      1 x ESTABLISHED
    Looping connections: 57 (10 duplicates)
        127.0.0.1                      --> 127.0.0.1:9355      :   20                                              1 x ESTABLISHED, 8 x TIME_WAIT, 11 x CLOSE_WAIT
        127.0.0.1                      --> 127.0.0.1:4713      :   10                                             10 x CLOSE_WAIT
        127.0.0.1                      --> 127.0.0.1:9353      :    9                                              4 x TIME_WAIT, 5 x CLOSE_WAIT
        127.0.0.1                      --> 127.0.0.1:3306      :    8                                              6 x ESTABLISHED, 1 x TIME_WAIT, 1 x CLOSE_WAIT
        127.0.0.1                      --> 127.0.0.1:5445      :    5                                              1 x ESTABLISHED, 4 x TIME_WAIT
        127.0.0.1                      --> 127.0.0.1:9354      :    2                                              2 x CLOSE_WAIT
        127.0.0.1                      --> 127.0.0.1:7998      :    1                                              1 x TIME_WAIT
        127.0.0.1                      --> 127.0.0.1:3351      :    1                                              1 x ESTABLISHED
        127.0.0.1                      --> 127.0.0.1:32000     :    1                                              1 x ESTABLISHED

## License

Copyright 2012<br>
M-PLIFY S.A.<br>
21, rue Glesener<br>
L-1631 Luxembourg

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Change log

<table>
<tr>
<td>2013-02-12</td>
<td>Correctly handle "netstat --wide", which may or may not work depending on the system. 
Correctly parse netstat output with IPv6 addresses.</td>
</tr>
<tr>
<td>2013-02-28</td>
<td>IPv4 addresses assigned to the local machine are obtained via IO::Interface::Simple. 
Complemented this with a readout of /proc/net/if_inet6 for the IPv6 addresses.
Netstat output parsing went wrong on Ubuntu (the IPv6 loopback is apparently shown as
127.0.0.1); fixed. (Maybe one should not bother with netstat at all and use /proc directly)</td>
</tr>
<tr>
<td>2013-02-28</td>
<td>Printout made nicer; fields are aligned whether IPv6 addresses show up or not.</td>
</tr>
<tr>
<td>2013-03-01</td>
<td>127.0.0.1 was no longer recognized as of type LOOPBACK; fixed. Improved debug messages.</td>
</tr>
<tr>
<td>2014-03-04</td>
<td>
When running teamviewer client, connections that are localhost->localhost show up that may have: No corresponding server socket; May only go "one way", i.e. the second entry of the typical bidirectional TCP connection is missing. How is that possible? ...the script could not handle that. FIXED! Also: Net::IP 1.25 declares that an IP address on 127.0.0.1 is "PRIVATE", not on the "LOOPBACK". This is weird, and is now being forcefully "fixed". Maybe this will go away im later versions!
</td>
<tr>
<td>2018-10-27</td>
<td>Complete review; added options and made it possible to have the program loop instead of having to use `watch`</td>
</table>

## TODO

<table>
<tr>
<td>When the reverse DNS lookup fails, one should traceroute to find the last IP that reverse-resolves.
</tr>
<tr>
<td>Also list the process owning the connection; info about this can be obtained with `lsof(8)`</td>
</tr>
</table>




