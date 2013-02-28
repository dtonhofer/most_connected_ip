#!/usr/bin/perl -w

################################################################################
# Extremely simple script to process (Linux) netstat output to show the 
# established TCP connections and their state on the local machine, grouped by
# endpoint (IP:port).
#
# Hosted at GitHub: https://github.com/dtonhofer/most_connected_ip.git
#
# Best used with "watch" for continual updates, like this:
#
#   watch -n 1 "perl most_connected_ip.pl 2>/dev/null"
#
# The above suppresses error messages and makes "watch" run the script
# every second. Of course a simple
#
#   watch most_connected_ip.pl 
#
# should work too.
################################################################################
# Copyright 2012 M-PLIFY S.A.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
################################################################################

use strict;
use List::Util qw[min max];
use Net::DNS::Resolver;    # http://search.cpan.org/~nlnetlabs/Net-DNS-0.72/lib/Net/DNS/Resolver.pm
use Net::IP qw(:PROC);     # http://search.cpan.org/dist/Net-IP/IP.pm
use IO::Interface::Simple; # http://search.cpan.org/~lds/IO-Interface/Interface/Simple.pm 
                           # Run: yum install  perl-Net-DNS.i686  perl-Net-IP   perl-IO-Interface


my $debug      = 0;        # Set to 1 for debugging output to STDERR
my $dnsNameLen = 50;       # Determines the size of the hostname printed to STDOUT
my $portSep    = "/";      # How to separate IP address and port (traditionally ":", but that is confusing)

# ----
# Obtain IP addresses assigned to local interfaces as a set. The set is implemented as a hash
# which maps "IP address as string" --> Net::IP instance. This includes the loopback address.
# ----

my $localIpAddresses = obtainLocalIpAddresses($debug);

# ----
# For querying DNS names: a local cache and the resolver itself (not sure the local cache
# is needed as the DNS resolver has its own cache, right?)
# The "reverseIpMap" maps a Net::IP instance to its reverse name and the date of last use.
# ----

my $reverseIpMap = { }; 
my $dnsResolver  = Net::DNS::Resolver->new;

# ----
# Hoover up the "netstat" output into an array of lines.
# In some cases, the "--wide" option is needed to get correct output.
# ----

my @lines;

{
   @lines = `netstat --help 2>&1`; # return value is 4

   my $useWide = ''; 

   foreach (@lines) { $useWide = ' --wide ' if ($_ =~ /\-\-wide/) }

   @lines = `netstat --tcp $useWide -n -a`;

   if ($? != 0) {
      print STDERR "Could not run 'netstat': $!\n";
      exit 1
   }
}

# ----
# Pre-process netstat lines, collecting "connections" and "listeners" into separate hashes.
# ----

my $allConnections = {}; # information about TCP connections as hash, keyed by a constructed string
my $allListeners   = {}; # information about TCP sockets (listeners) as hash, keyed by a constructed string

foreach my $line (@lines) {
   chomp $line;
   analyzeNetstatLine($line, $allConnections, $allListeners, $debug)
}

if ($debug) {
   foreach my $key (sort keys %$allConnections) {
      print STDERR "Connection : $key\n"
   }
   foreach my $key (sort keys %$allListeners) {
      print STDERR "Listener   : $key\n"
   }
}

# ----
# Post-process information now in "allConnections" and "allListeners". The values in these hashes
# are themselves hashes mapping strings to detail information (i.e. attribute-value pairs).
# Decorating these hashes with additional info.
# ----

foreach my $key (keys %$allConnections) {
   my $desc = $$allConnections{$key};
   #
   # Set the value of the key "type" in the "desc" hash:
   # type == "looping"  : both remote IP and local IP are the loopback address
   # type == "distant"  : neither the remote IP nor the local IP are the loopback address
   #  
   determineType($desc); 
   #
   # Set the value of the key "direction" in the "desc" hash:
   # direction == "inbound"    a connection for which the "local endpoint" is the server side
   # direction == "outbound"   a connection for which the "remote endpoint" is the server side
   # direction == "duplicate"  a connection with type == "looping" which is the symmetric representation of another one
   #
   determineDirection($allListeners,$allConnections,$localIpAddresses,$desc,$debug) 
}

if ($debug) {
   foreach my $key (sort keys %$allConnections) {
      my $desc = $$allConnections{$key};
      if ($$desc{direction} ne 'duplicate') {
         print "$key : type = $$desc{type} , direction = $$desc{direction}\n"
      }
   }
}

# ----
# Result generation: Group and print; the data is analyzed fully before printing in 
# order to establish the width of the "local endpoint" and "remote endpoint" fields
# ----

my $connCountMap     = {}; # map direction to number of connections
my $groupByMap       = {}; # map direction to a hash which maps grouping key to a value-holding hash
my $loopConnCount;         # number of looping connections
my $dupLoopConnCount;      # number of looping connections shown twice by netstat (one of the lines is thrown away)
my $loopGroupBy;           # hash which maps grouping key to a value-holding hash
my $maxLocalEpWidth  = 0;  # how large shall "local endpoint" field be
my $maxRemoteEpWidth = 0;  # how large shall "remote endpoint" field be

for my $direction ('inbound', 'outbound') {
   my $res = groupDistantConnections($allConnections,$direction,$reverseIpMap,$dnsResolver);
   $$groupByMap{$direction}   = $$res{groupBy};
   $$connCountMap{$direction} = $$res{connCount};
   $maxLocalEpWidth           = max($maxLocalEpWidth, $$res{maxLocalEpWidth});
   $maxRemoteEpWidth          = max($maxRemoteEpWidth,$$res{maxRemoteEpWidth});
}

{
   my $res = groupLoopingConnections($allConnections,$reverseIpMap,$dnsResolver);
   $loopConnCount     = $$res{loopConnCount};
   $dupLoopConnCount  = $$res{dupLoopConnCount};
   $loopGroupBy       = $$res{loopGroupBy};
   $maxLocalEpWidth   = max($maxLocalEpWidth, $$res{maxLocalEpWidth});
   $maxRemoteEpWidth  = max($maxRemoteEpWidth,$$res{maxRemoteEpWidth});
}

for my $direction ('inbound', 'outbound') {
   if ($$connCountMap{$direction} > 0) {
      print "Distant $direction connections: " . $$connCountMap{$direction} . "\n";
      printDistantConnections($$groupByMap{$direction},$direction,$maxLocalEpWidth,$maxRemoteEpWidth)
   }
}

if ($loopConnCount > 0) {
   print "Looping connections: $loopConnCount";
   print " ($dupLoopConnCount duplicate lines skipped)" if $dupLoopConnCount;
   print "\n";
   printLoopingConnections($loopGroupBy,$maxLocalEpWidth,$maxRemoteEpWidth);
}

exit 0;


# -----------------------------------------------------------------------------
# netstat line parsing; write to STDERR if this fails.
# On a single netstat line describing a connection, one finds:
#   protocol        - may be "tcp" or "tcp6"
#   receivq         - a positive integer
#   sendq           - a positive integer
#   local address   - may be "IPv4:PORT", "::ffff:IPv4:PORT", "IPv6:PORT"
#   foreign address - may be "IPv4:PORT", "::ffff:IPv4:PORT", "IPv6:PORT"
#   TCP state       - a known string
# On a single netstat line describing a server socket, one finds:
#   protocol        - may be "tcp" or "tcp6"
#   "0"
#   "0"
#   local address   - may be "IPv4:PORT", "::ffff:IPv4:PORT", "IPv6:PORT"
#   foreign address - "0.0.0.0:*", ":::*" 
#   "LISTEN"
# -----------------------------------------------------------------------------

sub analyzeNetstatLine {
   my ($line,$allConnections,$allListeners,$debug) = @_;
   #
   # Try to recognize a "connection" line
   #
   {
      my ($localIpTxt,$localPort,$remoteIpTxt,$remotePort,$state,$isConnection);
      $isConnection = 0;
      if ($line =~ /^(tcp|tcp6)\s+\d+\s+\d+\s+(::ffff:)?(\d+\.\d+\.\d+\.\d+):(\d+)\s+(::ffff:)?(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\S+?)\s*$/) {
         $localIpTxt   = $3;
         $localPort    = $4 * 1;
         $remoteIpTxt  = $6;
         $remotePort   = $7 * 1;
         $state        = $8;
         $isConnection = 1
      }
      elsif ($line =~ /^(tcp|tcp6)\s+\d+\s+\d+\s+([0-9abcdef:]+?):(\d+)\s+([0-9abcdef:]+?):(\d+)\s+(\S+?)\s*$/) {
         $localIpTxt   = $2; 
         $localPort    = $3 * 1;
         $remoteIpTxt  = $4;
         $remotePort   = $5 * 1;
         $state        = $6;
         $isConnection = 1
      }
      # If a connection was indeed recognized, process and we are done
      if ($isConnection) {
         my $localIp  = new Net::IP($localIpTxt); 
         die "Could not transform local IP '$localIpTxt'\n" unless $localIp;
         my $remoteIp = new Net::IP($remoteIpTxt);
         die "Could not transform remote IP '$remoteIpTxt'\n" unless $remoteIp;
         my $key      = "[" . $localIp->ip . "][$localPort][" . $remoteIp->ip . "][$remotePort]";
         die "There already is an entry registered under '$key'" if exists $$allConnections{$key};
         $$allConnections{$key} = { localIp    => $localIp, 
                                    localPort  => $localPort,
                                    remoteIp   => $remoteIp,
                                    remotePort => $remotePort,
                                    state      => $state };
         return # --> OUTTA HERE
      }
   }
   #
   # Otherwise, try to recognize a "listening socket" line
   #
   {
      my ($localIpRaw,$localPort,$isListen);
      $isListen = 0;
      if ($line =~ /^(tcp|tcp6)\s+0\s+0\s+(::ffff:)?(\d+\.\d+\.\d+\.\d+):(\d+)\s+(0\.0\.0\.0:\*|:::\*)\s+LISTEN\s*$/) {
         $localIpRaw = $3;
         $localPort  = $4 * 1;
         $isListen   = 1;
      }
      elsif ($line =~ /^(tcp|tcp6)\s+0\s+0\s+([0-9abcdef:]+?):(\d+)\s+:::\*\s+LISTEN\s*$/) {
         $localIpRaw = $2;
         $localPort  = $3 * 1;
         $isListen   = 1;
      }
      # If a "listening socket" was indeed recognized, process and we are done
      if ($isListen) {
         my ($key,$localIp);
         if ($localIpRaw eq '0.0.0.0') {
            # "Listen on any IP address" -> $localIp = undef
            # Net:IP cannot deal with that representation
            # even "Net::IP('0.0.0.0/8')" is considered a *private* address, but it should not be
            $localIp = undef
         }
         else {
            $localIp = new Net::IP($localIpRaw); 
            die "Could not transform local IP '$localIpRaw'\n" unless $localIp;
            # print STDERR $2 . " ---> " . $localIp->ip . "  " . $localIp->iptype() . "\n";
         }
         if (!defined $localIp || $localIp->iptype eq "UNSPECIFIED") {
            $key     = "[][$localPort]";
            $localIp = undef
            # the unspecified address may appear twice; for IPv6 and IPv4
         }
         else {
            $key  = "[" . $localIp->ip . "][$localPort]";
            die "The key '$key' has already been seen!\n" if exists $$allListeners{$key};
         }
         $$allListeners{$key} = { localIp => $localIp, localPort => $localPort };
         return # --> OUTTA HERE
      }
   }
   #
   # Otherwise either ignore the line or warn
   #
   if ($line =~ /^Activ/ || $line =~ /^Proto/) {
      # NOP
   }
   else {
      print STDERR "Unmatched: '$line'\n";
   }
}
 
# -----------------------------------------------------------------------------
# Is this a "looping" (loopback address on both sides) or "distant" (something 
# other than the loopback address on both sides) connection?
# -----------------------------------------------------------------------------

sub determineType {
   my($desc) = @_;
   my $localIp    = $$desc{localIp};
   my $remoteIp   = $$desc{remoteIp};
   my $localType  = $localIp->iptype;
   my $remoteType = $remoteIp->iptype;
   if ($localType eq "LOOPBACK" && $remoteType eq "LOOPBACK") {
      $$desc{type} = "looping"
   }
   elsif ($localType eq "LOOPBACK" || $remoteType eq "LOOPBACK") {
      die "Found bizarre half-loopback connection $localIp -> $remoteIp\n";
   }
   else {
      $$desc{type} = "distant"
   }
}

# -----------------------------------------------------------------------------
# We know whether the type of the connection is "looping" (loopback address
# on both sides) or "distant" (something other than the loopback address on
# both sides).
#
# What we additionally want to know is whether the "local endpoint" or the 
# "remote endpoint" is the server side. If the "local endpoint" is the
# server side, we label this an "inbound" connection. If the "remote
# endpoint" is the server side, we label this an "outbound" connection.
#
# In the case of "distant" connections:
# - - - - - - - - - - - - - - - - - - -
#
# Find out whether a "listener" matches the local endpoint. If so, this is
# an "inbound" connection. Otherwise, classify this as an "outbound" 
# connection (even if the remote endpoint's IP address actually matches an
# IP address on a local interface).
#
# Cases for the local endpoint:
#
#    L1:  Local endpoint matches a listener (IP:PORT or *:PORT)
#    L2:  Local endpoint does not match any listener
#
# Cases for the remote endpoint:  
#
#    R0:  Remote endpoint is not in the list of IP addresses visible on the interfaces
#    R1:  Remote endpoint is in the list of IP addresses and matches a listener (IP:PORT or *:PORT)
#    R2:  Remote endpoint is in the list of IP addresses but does not match any listener
#
# Conclusions (In,Out):
#
#       |  L1 |  L2 |
#    ---+-----+-----+
#    R0 |  I  |  O  |
#    ---+-----+-----+
#    R1 |  ?  |  O  |
#    ---+-----+-----+
#    R2 |  I  |  ?  |
#    ---+-----+-----+
#
# In the case of "looping" connections:
# - - - - - - - - - - - - - - - - - - -
#
# Here netstat actually may list a connection twice, with different syntax:
#
#   For example one sees two connections to MySQL:
#
#   tcp   0   0 127.0.0.1:3306           127.0.0.1:60928         ESTABLISHED  
#   tcp   0   0 ::ffff:127.0.0.1:60928   ::ffff:127.0.0.1:3306   ESTABLISHED  
#
# In this case, we throw away the representation where the server side
# is on the local endpoint. Otherwise, proceed as above. 
# -----------------------------------------------------------------------------

sub determineDirection {
   my($allListeners,$allConnections,$localIpAddresses,$desc,$debug) = @_;
   #
   # Create a key from the "local endpoint"
   #  
   my $localIp          = $$desc{localIp};
   my $localPort        = $$desc{localPort};
   my $localEpKey       = "[" . $localIp->ip . "][$localPort]";
   my $localDefaultKey  = "[][$localPort]";
   #
   # Create a key from the "remote endpoint"
   #
   my $remoteIp         = $$desc{remoteIp};
   my $remotePort       = $$desc{remotePort};
   my $remoteEpKey      = "[" . $remoteIp->ip . "][$remotePort]";
   my $remoteDefaultKey = "[][$remotePort]";
   #
   # Check that the local IP is indeed a known local IP
   #
   die "The local IP '" . $localIp->ip . "' is not in the list of local IP addresses\n" unless exists $$localIpAddresses{$localIp->ip};
   #
   # Check whether an endpoint matches a listener
   #
   my $localEpMatchesListener  = exists $$allListeners{$localDefaultKey}  || exists $$allListeners{$localEpKey};
   my $remoteEpMatchesListener = exists $$allListeners{$remoteDefaultKey} || exists $$allListeners{$remoteEpKey};
   #
   # Classify
   #
   if ($$desc{type} eq 'distant') {

      my $remoteEpIsRemote = ! exists $$localIpAddresses{ $remoteIp->ip };
      # print "Remote IP is remote: $remoteEpIsRemote in case of " . $remoteIp->ip . "\n";

      if ($remoteEpIsRemote) {
         if ($localEpMatchesListener) {
            print STDERR "Deducing distant :   $localEpKey <------- $remoteEpKey\n" if $debug;
            $$desc{direction} = "inbound";
         }
         else {
            print STDERR "Deducing distant :   $localEpKey -------> $remoteEpKey\n" if $debug;
            $$desc{direction} = "outbound";
         }
      }
      else {
          if ($localEpMatchesListener && !$remoteEpMatchesListener) {
            print STDERR "Deducing distant :   $localEpKey <------- $remoteEpKey\n" if $debug;
            $$desc{direction} = "inbound";
         }
         elsif (!$localEpMatchesListener && $remoteEpMatchesListener) {
            print STDERR "Deducing distant :   $localEpKey -------> $remoteEpKey\n" if $debug;
            $$desc{direction} = "outbound";
         }        
         else {
            die "Woah! localEpMatchesListener = '$localEpMatchesListener' and " .
                "remoteEpMatchesListener = '$remoteEpMatchesListener' " .
                " with local endpoint $localEpKey and remote endpoint $remoteEpKey\n";
         }
      }
   }
   elsif ($$desc{type} eq 'looping') {
      if ($localEpMatchesListener && !$remoteEpMatchesListener) {
         my $invKey  = $remoteEpKey . $localEpKey;
         if (! exists $$allConnections{$invKey}) {
            # Only one side of the connection is listed
            print STDERR "Deducing looping :   $localEpKey <------- $remoteEpKey\n" if $debug;
            $$desc{direction} = "inbound";
         }
         else {
            # Both sides of the conneciton are listed; select the other one
            print STDERR "Deducing looping :   $localEpKey <~~~~~~~ $remoteEpKey\n" if $debug;
            $$desc{direction} = "duplicate";
         }
      }
      elsif (!$localEpMatchesListener && $remoteEpMatchesListener) {
         my $invKey  = $remoteEpKey . $localEpKey;
         # Irrespective of whether both or just one side of the connection are listed, select this one!
         print STDERR "Deducing looping :   $localEpKey -------> $remoteEpKey\n" if $debug;
         $$desc{direction} = "outbound";
      }
      else {
         die "Woah! localEpMatchesListener = '$localEpMatchesListener' and " .
             "remoteEpMatchesListener = '$remoteEpMatchesListener' " .
             " with local endpoint $localEpKey and remote endpoint $remoteEpKey\n";
      }
   }
   else {
      die "Unknown type '$$desc{type}' found\n"
   }
}

# -----------------------------------------------------------------------------
# Given an IP address, find its symbolic name (i.e. the PTR record)
# Returns "" if none found.
# -----------------------------------------------------------------------------

sub findReverse {
   my ($ip,$reverseIpMap,$dnsResolver) = @_;
   #
   # The passed "ip" is a Net::IP structure
   #
   my $dnsName;
   #
   # Don't bother to look up local addresses etc
   #
   my $type = $ip->iptype();
   # print "Type of " . $ip->ip() . ": $type\n";   
   # return '' if ($type ne 'PUBLIC');
   #
   # Look in program-local cache first
   #
   my $ipName = $ip->ip();
   my $cached = $$reverseIpMap{$ipName};
   if ($cached) {
      $dnsName = $$cached[0];
      $$reverseIpMap{$ipName} = [ $dnsName, time() ];
      return $dnsName
   }
   #
   # Not in cache; ask DNS
   # query() behaves appropriately and looks up the PTR record for "$4.$3.$2.$1.in-addr.arpa"
   # "If the name looks like an IP address (IPv4 or IPv6), then an appropriate PTR query will be performed."
   #
   my $packet = $dnsResolver->query($ipName);
   if (!$packet) {
      $dnsName = "?";
      $$reverseIpMap{$ipName} = [ $dnsName, time() ]
   }
   else {
      $dnsName = "";
      my $addComma = 0;
      my @answer = $packet->answer;
      for my $rr (@answer) {
         if ($rr->type eq 'PTR') {
            if ($addComma) {
               $dnsName .= ","
            }
            $dnsName .= $rr->ptrdname;
            $addComma = 1
            # for my $key (keys %$rr) {
            #   print "$key = $$rr{$key} \n";
            # }
         }
      } 
   }
   return $dnsName
}

# -----------------------------------------------------------------------------
# Group the distant connections, basically doing a manual SQL GROUP BY
# Only considers connections matching "reqDirection", i.e. either 'outbound'
# or 'inbound' ones.
#
# Returns a hash with:
#
# At "groupBy"   : A hash which maps a string (the grouping key) to another 
#                  hash listing "local endpoint", "remote endpoint", "states"
#                  number of connection grouped, reverse DNS name and the
#                  grouping key itself
#
# At "connCount" : Number of connections found in total
#
# At "maxLocalEpWidth"  : the largest string width found for the "local endpoint"
#
# At "maxRemoteEpWidth" : the largest string width found for the "remote endpoint"
# -----------------------------------------------------------------------------

sub groupDistantConnections {
   my ($allConnections,$reqDirection,$reverseIpMap,$dnsResolver) = @_;
   my $groupBy   = {};
   my $connCount = 0;
   my $maxLocalEpWidth  = 0;
   my $maxRemoteEpWidth = 0;
   for my $desc (values %$allConnections) {
      my ($localIp,$localPort,$remoteIp,$remotePort,$state,$direction,$type) = unpackDesc($desc);
      next if (($type ne 'distant') || ($direction ne $reqDirection));
      $connCount++;
      my $newKey;
      if ($reqDirection eq 'outbound') {
         # Group by remote endpoint and by local IP (basically a manual GROUP BY)
         $newKey = $remoteIp->ip . "," . $remotePort . "," . $localIp->ip;
         # Create the grouping record if it doesn't exist yet
         if (!exists $$groupBy{$newKey}) {
            my $localEp  = $localIp->short;
            my $remoteEp = $remoteIp->short . $portSep . $remotePort;
            $maxLocalEpWidth  = max($maxLocalEpWidth,  length($localEp));
            $maxRemoteEpWidth = max($maxRemoteEpWidth, length($remoteEp));
            $$groupBy{$newKey} = { 
               localEp       => $localEp,
               remoteEp      => $remoteEp,
               stateSubHash  => { }, # this will contain the state counters, filled by registerState() below
               count         => 0,
               dnsName       => findReverse($remoteIp,$reverseIpMap,$dnsResolver),
               key           => $newKey
            }
         }
      }
      elsif ($reqDirection eq 'inbound') {
         # Group by local endpoint and by remote IP (basically a manual GROUP BY)
         $newKey = $localIp->ip . "," . $localPort . "," . $remoteIp->ip;
         # Create the grouping record if it doesn't exist yet
         my $localEp  = $localIp->short . $portSep . $localPort;
         my $remoteEp = $remoteIp->short;
         $maxLocalEpWidth  = max($maxLocalEpWidth,  length($localEp));
         $maxRemoteEpWidth = max($maxRemoteEpWidth, length($remoteEp));
         if (!exists $$groupBy{$newKey}) {
            $$groupBy{$newKey} = { 
               localEp       => $localEp,
               remoteEp      => $remoteEp,
               stateSubHash  => { }, # this will contain the state counters, filled by registerState() below
               count         => 0,
               dnsName       => findReverse($remoteIp,$reverseIpMap,$dnsResolver),
               key           => $newKey
            }
         }
      }
      else {
         die "Unknown direction '$reqDirection'\n"
      }
      # retrieve the grouping record which must exist now and increment counters
      my $gDesc = $$groupBy{$newKey};
      $$gDesc{count}++;
      registerState($$gDesc{stateSubHash},$state)
   }
   return { groupBy => $groupBy, connCount => $connCount, 
            maxLocalEpWidth => $maxLocalEpWidth, maxRemoteEpWidth => $maxRemoteEpWidth }
}

# -----------------------------------------------------------------------------
# Group the looping connections, basically doing a manual SQL GROUP BY
# -----------------------------------------------------------------------------

sub groupLoopingConnections {
   my ($allConnections,$reverseIpMap,$dnsResolver) = @_;
   my $groupBy          = {};
   my $connCount        = 0;
   my $dupConnCount     = 0;
   my $maxLocalEpWidth  = 0;
   my $maxRemoteEpWidth = 0;
   for my $desc (values %$allConnections) {
      my ($localIp,$localPort,$remoteIp,$remotePort,$state,$direction,$type) = unpackDesc($desc);
      next if $type ne 'looping';
      if ($direction eq 'duplicate') {
         $dupConnCount++;
         next
      }
      $connCount++;
      my $newKey;
      if ($direction eq 'outbound') {
         # Group by remote endpoint and by local IP
         $newKey = $remoteIp->ip . "," . $remotePort . "," . $localIp->ip;
         if (!exists $$groupBy{$newKey}) {
            # Create the grouping record if it doesn't exist yet
            my $localEp  = $localIp->short;
            my $remoteEp = $remoteIp->short . $portSep . $remotePort;
            $maxLocalEpWidth  = max($maxLocalEpWidth,  length($localEp));
            $maxRemoteEpWidth = max($maxRemoteEpWidth, length($remoteEp));
            $$groupBy{$newKey} = { 
               localEp       => $localEp,
               remoteEp      => $remoteEp,
               stateSubHash  => { }, # this will contain the state counters, filled by registerState() below
               count         => 0,
               key           => $newKey
            }
         }
      }
      elsif ($direction eq 'inbound') {
         # Reverse this entry...
         $newKey = $localIp->ip . "," . $localPort . "," . $remoteIp->ip;
         if (!exists $$groupBy{$newKey}) {
            # Create the grouping record if it doesn't exist yet
            my $localEp  = $remoteIp->short;
            my $remoteEp = $localIp->short . $portSep . $localPort;
            $maxLocalEpWidth  = max($maxLocalEpWidth,  length($localEp));
            $maxRemoteEpWidth = max($maxRemoteEpWidth, length($remoteEp));
            $$groupBy{$newKey} = { 
               localEp       => $localEp,
               remoteEp      => $remoteEp,
               stateSubHash  => { }, # this will contain the state counters, filled by registerState() below
               count         => 0,
               key           => $newKey
            }
         }
      }
      else {
         die "Unknown direction '$direction'\n";
      }
      my $gDesc = $$groupBy{$newKey};
      $$gDesc{count}++;
      registerState($$gDesc{stateSubHash},$state)
   }
   return { loopGroupBy => $groupBy, loopConnCount => $connCount, dupLoopConnCount => $dupConnCount, 
            maxLocalEpWidth => $maxLocalEpWidth, maxRemoteEpWidth => $maxRemoteEpWidth }
}

# -----------------------------------------------------------------------------
# Helper
# -----------------------------------------------------------------------------

sub unpackDesc {
   my($desc) = @_;
   my $localIp    = $$desc{localIp};
   my $localPort  = $$desc{localPort};
   my $remoteIp   = $$desc{remoteIp};
   my $remotePort = $$desc{remotePort};
   my $state      = $$desc{state};
   my $direction  = $$desc{direction};
   my $type       = $$desc{type};
   return ($localIp,$localPort,$remoteIp,$remotePort,$state,$direction,$type)
}

# -----------------------------------------------------------------------------
# Helper
# -----------------------------------------------------------------------------

sub registerState {
   my($stateSubHash,$state) = @_;
   if (!exists $$stateSubHash{$state}) {
       $$stateSubHash{$state} = 0
   }
   $$stateSubHash{$state}++
}

# -----------------------------------------------------------------------------
# Printer for "distant" connections
# -----------------------------------------------------------------------------

sub printDistantConnections {
   my($groupBy,$direction,$maxLocalEpWdith,$maxRemoteEpWidth) = @_;
   my $arrowMap  = { outbound => "-->", inbound => "<--" };
   my $arrow     = $$arrowMap{$direction};
   my $maxLocal  = $maxLocalEpWidth  + 1;
   my $maxRemote = $maxRemoteEpWidth + 1;
   my @gDescList = reverse (sort sortByCountThenKey (values %$groupBy));
   my $format    = buildFormatString($maxLocalEpWidth,$maxRemoteEpWidth);
   for my $gDesc (@gDescList) {
      my $localEp  = $$gDesc{localEp}; 
      my $remoteEp = $$gDesc{remoteEp};
      my $count    = $$gDesc{count};
      my $dnsName  = $$gDesc{dnsName};
      if (!$dnsName) {
         $dnsName = ''
      }
      else {
         if (length($dnsName) > $dnsNameLen) {
            $dnsName = substr($dnsName, $dnsNameLen)
         }
      }      
      my $stateText = buildStateText($$gDesc{stateSubHash});
      print sprintf($format, $localEp, $arrow, $remoteEp, $count, $dnsName, $stateText);
   }
}

# -----------------------------------------------------------------------------
# Printer for "looping" connections
# -----------------------------------------------------------------------------

sub printLoopingConnections {
   my($groupBy,$maxLocalEpWidth,$maxRemoteEpWidth) = @_;
   my @gDescList = reverse (sort sortByCountThenKey (values %$groupBy));
   my $format    = buildFormatString($maxLocalEpWidth,$maxRemoteEpWidth);
   for my $gDesc (@gDescList) {
      my $localEp   = $$gDesc{localEp}; 
      my $remoteEp  = $$gDesc{remoteEp};
      my $count     = $$gDesc{count};
      my $stateText = buildStateText($$gDesc{stateSubHash});
      print sprintf($format, $localEp, "-->", $remoteEp, $count, '', $stateText);
   }
}

# -----------------------------------------------------------------------------
# Build state text
# -----------------------------------------------------------------------------

sub buildStateText {
   my($stateSubHash) = @_;
   my $text = '';
   my $addComma = '';
   for my $state (sort sortByState keys %$stateSubHash) {
       $text = $text . $addComma . $$stateSubHash{$state} . " x " . $state;
       $addComma = ", ";
   }
   return $text 
}

# -----------------------------------------------------------------------------
# Build format string
# -----------------------------------------------------------------------------

sub buildFormatString {
   my($maxLocalEpWidth,$maxRemoteEpWidth) = @_;
   my $maxLocal  = $maxLocalEpWidth  + 1;
   my $maxRemote = $maxRemoteEpWidth + 1;
   my $format    = "   %-${maxLocal}s %3s %-${maxRemote}s : %4d        %-${dnsNameLen}s %s\n";
   return $format
}

# -----------------------------------------------------------------------------
# Sorter of values in "groupBy" hashes
# -----------------------------------------------------------------------------

sub sortByCountThenKey {
   my $a_c = $$a{count};
   my $b_c = $$b{count};
   if ($a_c != $b_c) { 
      return $a_c <=> $b_c
   }
   else {
      return $$a{key} cmp $$b{key}
   }
}

# ----------------------------------------------------------------------------
# Sort TCP state strings, the ones mostly seen have negative sort values
# ----------------------------------------------------------------------------

sub sortByState {
   # sortedStateStrings is not visible to sortByState() if in the global context...
   my $sortedStateStrings = { 'CLOSED'      =>   1,
                              'LISTEN'      =>   2,
                              'SYN_RCVD'    =>   3, 'SYN_RECV' => 3,
                              'SYN_SENT'    =>   4,
                              'ESTABLISHED' =>  -2,
                              'CLOSE_WAIT'  =>   5,
                              'LAST_ACK'    =>   6,
                              'FIN_WAIT1'   =>   7,
                              'FIN_WAIT2'   =>   8,
                              'CLOSING'     =>   9,
                              'UNKNOWN'     =>   10,
                              'TIME_WAIT'   =>  -1  };
   my $a_x = $$sortedStateStrings{$a}; if (!defined($a_x)) { $a_x = 100 }
   my $b_x = $$sortedStateStrings{$b}; if (!defined($b_x)) { $b_x = 100 }
   return $a_x <=> $b_x
}

# -----------------------------------------------------------------------------
# Obtain local interfaces as a set mapping "IP address" --> 1; this includes
# the loopback address
# -----------------------------------------------------------------------------

sub obtainLocalIpAddresses {
   my ($debug) = @_;
   my $res = {}; # map which maps an IP string representation to a Net::IP object
   #
   # IO::Interface::Simple only collects IPv4 interface addresses; currently there 
   # is no practical listing under /proc for these; I suppose it uses 
   # getifaddrs(3)
   #
   {
      my @ifarray = IO::Interface::Simple->interfaces;
      for my $if (@ifarray) {
         if ($if->address) {
            my $ip = new Net::IP($if->address); 
            die "Could not transform the address " . $if->address . " of interface '$if' into a Net::IP\n" unless $ip;
            $$res{$ip->ip} = $ip;
            if ($debug) { 
               print STDERR "Interface '$if' with address '" . $if->address . "' registered with IP address string '" . $ip->ip . "'\n";
            }
         }
      }
   }
   #
   # IPv6 addresses can be gotten from /proc; this includes the loopback address
   #  
   my $procfile = "/proc/net/if_inet6";
   if (-f $procfile) {
      open(my $fh,"<$procfile") or die "Could not open file '$procfile': $!\n";
      my @if6array = <$fh>;
      close($fh);
      for my $line (@if6array) {
         if ($line =~ /^([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})\s+(\w\w)\s+(\w\w)\s+(\w\w)\s+(\w\w)\s+(\w+)/) {
            my $rawIp = "$1:$2:$3:$4:$5:$6:$7:$8";
            my $if    = $13;
            my $ip = new Net::IP($rawIp); 
            die "Could not transform the address " . $rawIp . " of interface '$if' into a Net::IP\n" unless $ip;
            $$res{$ip->ip} = $ip;
            if ($debug) { 
               print STDERR "Interface '$if' registered with IP address string '" . $ip->ip . "'\n";
            }
         }
      }
   }
   return $res;
}

