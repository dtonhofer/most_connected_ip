#!/usr/bin/perl -w

################################################################################
# Extremely simple script to process (Linux) netstat output to show 
# "most connected IPs"
#
# Best used with "watch" for continual updates.
################################################################################
# Maintainer: d.tonhofer@m-plify.com
#
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
use Net::DNS::Resolver;    # http://search.cpan.org/~nlnetlabs/Net-DNS-0.72/lib/Net/DNS/Resolver.pm
use Net::IP qw(:PROC);     # http://search.cpan.org/dist/Net-IP/IP.pm
use IO::Interface::Simple; # http://search.cpan.org/~lds/IO-Interface/Interface/Simple.pm 
                           # Run: yum install  perl-Net-DNS.i686  perl-Net-IP   perl-IO-Interface


my $debug = 0;          # Set to 1 for debugging output to STDERR
my $dnsNameLen = 50;    # Determines the size of the hostname printed to STDOUT

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
# ----

my @lines = `netstat --tcp -n -a`;

if ($? != 0) {
   print STDERR "Could not run netstat -- exiting: $!\n";
   exit 1
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
# Result generation: Group and print
# ----

for my $direction ('inbound', 'outbound') {
   my $res       = groupDistantConnections($allConnections,$direction,$reverseIpMap,$dnsResolver);
   my $groupBy   = $$res[0];
   my $connCount = $$res[1];
   print "Distant $direction connections: $connCount\n";
   printDistantConnections($groupBy,$direction,$dnsNameLen)
}

{
   my $res          = groupLoopingConnections($allConnections,$reverseIpMap,$dnsResolver);
   my $groupBy      = $$res[0];
   my $connCount    = $$res[1];
   my $dupConnCount = $$res[2];
   print "Looping connections: $connCount ($dupConnCount duplicates)\n";
   printLocalConnections($groupBy,$dnsNameLen)
}

exit 0;





# -----------------------------------------------------------------------------
# Line parsing; write to STDERR if this fails
# -----------------------------------------------------------------------------

sub analyzeNetstatLine {
   my ($line,$allConnections,$allListeners,$debug) = @_;
   my $localIp;
   my $localPort;
   my $remoteIp;
   my $remotePort;
   my $state;
   if ($line =~ /^tcp\s+\d+\s+\d+\s+(::ffff:)?(\d+\.\d+\.\d+\.\d+):(\d+)\s+(::ffff:)?(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\S+?)\s*$/ ||
       $line =~ /^tcp(6)?\s+\d+\s+\d+\s+([0-9abcdef:]+?):(\d+)\s+([0-9abcdef:]+?):(\d+)\s+(\S+?)\s*$/) {
      #
      # TCP over IPv4 -- the lines lists:
      # "receivq, sendq, local address (IPv4:PORT, ::ffff:IPv4:PORT, IPv6), foreign address (IPv4:PORT, ::ffff:IPv4:PORT, IPv6), state"
      #   
      my $localIp    = new Net::IP($2); 
      die "Could not transform local IP '$2'\n" unless $localIp;
      my $localPort  = $3 * 1;
      my $remoteIp   = new Net::IP($5);
      die "Could not transform remote IP '$5'\n" unless $remoteIp;
      my $remotePort = $6 * 1;
      my $state      = $7;
      my $key     = "[" . $localIp->ip() . "][$localPort][" . $remoteIp->ip() . "][$remotePort]";
      die "There already is an entry registered under '$key'" if exists $$allConnections{$key};
      $$allConnections{$key} = { localIp    => $localIp, 
                                 localPort  => $localPort,
                                 remoteIp   => $remoteIp,
                                 remotePort => $remotePort,
                                 state      => $state }
   }
   elsif ($line =~ /^tcp\s+0\s+0\s+(::ffff:)?(\d+\.\d+\.\d+\.\d+):(\d+)\s+(0\.0\.0\.0:\*|:::\*)\s+LISTEN\s*$/ ||
          $line =~ /^tcp(6)?\s+0\s+0\s+([0-9abcdef:]+?):(\d+)\s+:::\*\s+LISTEN\s*$/) {

      my $localIp;
      my $localPort  = $3 * 1;
      my $key;

      if ($2 eq '0.0.0.0') {
         # Net:IP cannot deal with that representation
         # even "Net::IP('0.0.0.0/8')" is considered a *private* address, but it should not be
         $localIp = undef
      }
      else {
         $localIp = new Net::IP($2); 
         die "Could not transform local IP '$2'\n" unless $localIp;
         # print STDERR $2 . " ---> " . $localIp->ip . "  " . $localIp->iptype() . "\n";
      }

      if (!defined $localIp || $localIp->iptype() eq "UNSPECIFIED") {
         $key     = "[][$localPort]";
         $localIp = undef
         # the unspecified address may appear twice; for IPv6 and IPv4
      }
      else {
         $key  = "[" . $localIp->ip . "][$localPort]";
         die "The key '$key' has already been seen!\n" if exists $$allListeners{$key};
      }
      $$allListeners{$key} = { localIp    => $localIp,
                               localPort  => $localPort }
   }
   elsif ($line =~ /^Activ/ || $line =~ /^Proto/) {
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
   my $localType  = $localIp->iptype();
   my $remoteType = $remoteIp->iptype();
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
   return '' if ($type ne 'PUBLIC');
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
# -----------------------------------------------------------------------------

sub groupDistantConnections {
   my ($allConnections,$sollDirection,$reverseIpMap,$dnsResolver) = @_;
   my $groupBy   = {};
   my $connCount = 0;
   for my $desc (values %$allConnections) {
      my ($localIp,$localPort,$remoteIp,$remotePort,$state,$direction,$type) = unpackDesc($desc);
      next if (($type ne 'distant') || ($direction ne $sollDirection));
      $connCount++;
      my $newKey;
      if ($sollDirection eq 'outbound') {
         # Group by remote endpoint and by local IP (basically a manual GROUP BY)
         $newKey = $remoteIp->ip . "," . $remotePort . "," . $localIp;
         # create the grouping record if it doesn't exist yet
         if (!exists $$groupBy{$newKey}) {
            $$groupBy{$newKey} = { 
               localEp       => $localIp->ip,
               remoteEp      => $remoteIp->ip . ":" . $remotePort,
               stateSubHash  => { }, # this will contain the state counters
               count         => 0,
               dnsName       => findReverse($remoteIp,$reverseIpMap,$dnsResolver),
               key           => $newKey
            }
         }
      }
      elsif ($sollDirection eq 'inbound') {
         # Group by local endpoint and by remote IP (basically a manual GROUP BY)
         $newKey = $localIp->ip . "," . $localPort . "," . $remoteIp;
         # create the grouping record if it doesn't exist yet
         if (!exists $$groupBy{$newKey}) {
            $$groupBy{$newKey} = { 
               localEp       => $localIp->ip . ":" . $localPort,
               remoteEp      => $remoteIp->ip,
               stateSubHash  => { }, # this will contain the state counters
               count         => 0,
               dnsName       => findReverse($remoteIp,$reverseIpMap,$dnsResolver),
               key           => $newKey
            }
         }
      }
      else {
         die "Unknown direction '$sollDirection'\n"
      }
      # retrieve the grouping record which must exist now and increment counters
      my $gDesc = $$groupBy{$newKey};
      $$gDesc{count}++;
      registerState($$gDesc{stateSubHash},$state)
   }
   return [ $groupBy, $connCount ]
}

# -----------------------------------------------------------------------------
# Group the looping connections, basically doing a manual SQL GROUP BY
# -----------------------------------------------------------------------------

sub groupLoopingConnections {
   my ($allConnections,$reverseIpMap,$dnsResolver) = @_;
   my $groupBy   = {};
   my $connCount = 0;
   my $dupConnCount = 0;
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
         # (do we need to group by IP? Maybe, if there are IPv4 and IPv6 connections)
         $newKey = $remoteIp->ip . "," . $remotePort . "," . $localIp;
         if (!exists $$groupBy{$newKey}) {
            $$groupBy{$newKey} = { 
               localEp       => $localIp->ip,
               remoteEp      => $remoteIp->ip . ":" . $remotePort,
               stateSubHash  => { },
               count         => 0,
               key           => $newKey
            }
         }
      }
      elsif ($direction eq 'inbound') {
         # Reverse this entry...
         $newKey = $localIp->ip . "," . $localPort . "," . $remoteIp;
         if (!exists $$groupBy{$newKey}) {
            $$groupBy{$newKey} = { 
               localEp       => $remoteIp->ip,
               remoteEp      => $localIp->ip . ":" . $localPort,
               stateSubHash  => { },
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
   return [ $groupBy, $connCount, $dupConnCount ]
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
   my($groupBy,$direction,$dnsNameLen) = @_;
   my @list = reverse (sort sortByCountThenKey (values %$groupBy));
   my $arrow;
   if ($direction eq 'outbound') {
      $arrow = "-->"
   }
   else {
      $arrow = "<--"
   }
   for my $gDesc (@list) {
      my $localEp  = $$gDesc{localEp}; 
      my $remoteEp = $$gDesc{remoteEp};
      my $count    = $$gDesc{count};
      my $dnsName  = '';
      $dnsName  = $$gDesc{dnsName};
      {
         if (!$dnsName) {
            $dnsName = ''
         }
         else {
            if (length($dnsName) > $dnsNameLen) {
               $dnsName = substr($dnsName, $dnsNameLen)
            }
         }      
      }
      my $stateText = ''; 
      {
         my $addComma = '';
         my $stateSubHash = $$gDesc{stateSubHash};
         for my $state (sort sortByState keys %$stateSubHash) {
            $stateText = $stateText . $addComma . $$stateSubHash{$state} . " x " . $state;
            $addComma = ", ";
         }
      }
      print sprintf("   %-30s %3s %-30s : %4d        %-${dnsNameLen}s %s\n", $localEp, $arrow, $remoteEp, $count, $dnsName, $stateText);
   }
}

# -----------------------------------------------------------------------------
# Printer for "local" connections
# -----------------------------------------------------------------------------

sub printLocalConnections {
   my($groupBy,$dnsNameLen) = @_;
   my @list = reverse (sort sortByCountThenKey (values %$groupBy));
   for my $gDesc (@list) {
      my $localEp  = $$gDesc{localEp}; 
      my $remoteEp = $$gDesc{remoteEp};
      my $count    = $$gDesc{count};
      my $stateText = ''; 
      {
         my $addComma = '';
         my $stateSubHash = $$gDesc{stateSubHash};
         for my $state (sort sortByState keys %$stateSubHash) {
            $stateText = $stateText . $addComma . $$stateSubHash{$state} . " x " . $state;
            $addComma = ", ";
         }
      }
      print sprintf("   %-30s %3s %-30s : %4d        %-${dnsNameLen}s %s\n", $localEp, "-->", $remoteEp, $count, '', $stateText);
   }
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
   my $res = {};
   my @ifarray = IO::Interface::Simple->interfaces;
   for my $if (@ifarray) {
      if ($if->address) {
         my $ip = new Net::IP($if->address); 
         die "Could not transform the address " . $if->address . " of interface '$if' into a Net::IP\n" unless $ip;
         $$res{$ip->ip()} = $ip;
         if ($debug) { 
            print STDERR "Interface '$if' with address '" . $if->address . "' registered with IP address string '" . $ip->ip . "'\n";
         }
      }
   }
   return $res;
}

