most_connected_ip
=================

Perl script to display the currently "most connected IPs" (actually the <em>active TCP connections</em> on
on the local machine.) This is done by scanning the `netstat(8)` output, the script is thus meant for a
Unix. 

It is best used with `watch(1)`  for continuous updates. You also need a wide screen (or a small font).

<em>Tested on: Fedora 17 and Red Hat Linux 6 and 5</em>

Change log
----------

2013-02-12 : Correctly handle "netstat --wide", which may or may not work depending on the system.
             Correctly parse netstat output with IPv6 addresses.

TODO
----

IO::Interface::Simple doesn't grok IPv6 addresses. Replace with a scrape of /proc

Sample output
-------------

Below is a sample output that shows two "inbound" TCP connections to ports 772 and 443, three "outbound"
TCP connections to some remote machines on ports 772 and 25, as well as a bunch of TCP connections going over
the loopback interface. 

Also shown are the TCP connections' states and the reverse-resolved name of the remote IP addresses.

Note the "10 duplicates" indication shown in the "looping connections" header. Sometimes there are connections
over the loopback interface for which `netstat` prints two lines, thus the script ignores one of them. 10
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


