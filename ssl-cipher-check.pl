#!/usr/bin/perl
#
#---------------------------------------
# SSL Cipher Check
#   Writen by Lee 'MadHat' Heath (madhat@unspecific.com)
# https://github.com/unspecific/ssl-ciper-check
#
# Patches/fixes provided by:
#   markus.theissinger in .de
#
# This script uses the openssl executable to connect to a server and test
# each of the SSL cipher methods supported by the local openssl client.
# By default it checks 443, for HTTPs, but will work on any SSL enabled
# port.  The default output is just a listing of each cipher and TLS1,
# SSLv2 and SSLv3 and SUCCESS or FAIL message.  It automatically creates
# a log called ssl_dump.log (over written with each run) that has the
# specific output of each openssl call.
#
# Copyright (c) 2009-2014, Lee MadHat Heath (madhat@unspecific.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the distribution.
#   * Neither the name of MadHat Productions nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  Note:  BEAST  and CRIME are coming.
#   BEAST takes advantage of a flaw in block ciphers
#        The vuln is in TLS1.0 only and only there when using block
#         ciphers with CBC.  Basically if the server used TLS1.0 and
#         supports any cipher other than RC4 it is potentially vulnerable.
#   CRIME takes advantage in how SSL compression is handled in TLS1.0
#
# As of October 2014 SSLv3 is considered weak due to POODLE
#
#
#---------------------------------------

use warnings;
use strict;
use Data::Dumper;
use Getopt::Std;
use Socket qw(:DEFAULT :crlf);

my $openssl = '/usr/bin/openssl';
my $gnutls = '/usr/bin/gnutls-cli-debug';
my $cafile = 'ca-bundle.crt';
my $DEBUG = 0;

my %ciphers;
my @ciphers;
my $cipher;

my @weak = ('ADH-AES128-SHA', 'ADH-AES256-SHA','ADH-DES-CBC-SHA',
    'ADH-DES-CBC3-SHA', 'ADH-RC4-MD5', 'EXP-ADH-DES-CBC-SHA',
    'EXP-ADH-RC4-MD5', 'EDH-RSA-DES-CBC-SHA', 'EXP-EDH-RSA-DES-CBC-SHA',
    'EDH-DSS-DES-CBC-SHA', 'EXP-EDH-DSS-DES-CBC-SHA', 'DES-CBC-SHA',
    'EXP-DES-CBC-SHA', 'EXP-RC2-CBC-MD5', 'EXP-RC4-MD5', 'DES-CBC-MD5',
    'EXP-RC2-CBC-MD5', 'EXP-RC4-MD5', 'NULL-SHA', 'NULL-MD5', 'AECDH-NULL-SHA',
    'EXPORT');
my %names = ('OU' => 'Organizational Unit (OU)',
          'O'  => 'Company (O)',
          'L'  => 'City (L)',
          'ST' => 'State (ST)',
          'CN' => 'Common Name (CN)',
          'C'  => 'Country (C)',
          '1.3.6.1.4.1.311.60.2.1.3'  => 'Country',
          '1.3.6.1.4.1.311.60.2.1.2'  => 'State',
          'serialNumber' => 'Serial Number',
          'emailAddress' => 'Contact',
          'street' => 'Street Address',
          'postalCode' => 'Postal Code',
          'businessCategory' => 'Business',
          'jurisdictionST' => 'State (ST)',
          'jurisdictionC'  => 'Country (C)',
          '2.5.4.9' => 'Address',
          '2.5.4.17' => 'Zip Code',
          '2.5.4.15' => 'Business Category'
    );
my %protocols = (
     'SSLv2' => {'on' => '-ssl2', 'off' => '-no_ssl2', 'support' => 'yes'},
     'SSLv3' => {'on' => '-ssl3', 'off' => '-no_ssl3', 'support' => 'yes'},
     'TLSv1' => {'on' => '-tls1', 'off' => '-no_tls1', 'support' => 'yes'},
     'TLSv1.1' => {'on' => '-tls1_1', 'off' => '-no_tls1_1', 'support' => 'yes'},
     'TLSv1.2' => {'on' => '-tls1_2', 'off' => '-no_tls1_2', 'support' => 'yes'}
);
my $protocol_count = 5;

###########################################################################

my $VERSION = '2.2';

my $host;
my %opts;

getopts('dgvwas',\%opts);

my $opt_a = $opts{'a'};
my $opt_d = $opts{'d'};
my $opt_g = $opts{'g'};
my $opt_s = $opts{'s'};
my $opt_v = $opts{'v'};
my $opt_w = $opts{'w'};

if (!$ARGV[0]) {
  print " : SSL Cipher Check: $VERSION\n";
  print " : written by Lee 'MadHat' Heath (at) Unspecific.com\n";
  print " :  - https://github.com/unspecific/ssl-ciper-check\n";
  print "Usage:\n";
  print "  $0 [ -dgvwas ] <host> [<port>]\n";
  print "default port is 443\n";
  print "-d  Add debug info (show it all, lots of stuff)\n";
  print "-v  Verbose.  Show more info about what is found\n";
  print "-g  GNUTLS.  Use gnutls-cli-debug (if installed) to show more info\n";
  print "-w  Show only weak ciphers enabled.\n";
  print "-a  Show all ciphers, enabled or not\n";
  print "-s  Show only the STRONG ciphers enabled.\n";
  print "\n";
  if (!-e $openssl) {
    print "WARNING: OpenSSL not found at $openssl, unable to run\n";
  }
  if (!-e $gnutls) {
    print "WARNING: gnutls not found at $gnutls, unable to run extra checks\n";
  }
  exit;
} else {
  $host = $ARGV[0];
  if ($host !~ /^[a-zA-Z0-9\-\.]+$/) {
    die "Please check hostanme ($host)\n\n"
  }
}
if ($opt_d) {
  $DEBUG = 1;
  $opt_a = 1;
  $opt_w = 0;
  $opt_v = 1;
  $opt_s = 0;
}
my $options = '';
my $disable_v2 = 'FALSE';
if (-e $cafile) {
  $options = "-CAfile $cafile ";
}
my $start = time;
my $port = $ARGV[1]?$ARGV[1]:443;
open (META, ">ssl_dump.log") if ($DEBUG);
print META localtime() . " START\n" if ($DEBUG);
print localtime() . " START\n" if ($opt_v);
print META "Testing $host:$port\n" if ($DEBUG);
print "Testing $host:$port\n";

if ($opt_v) {
  print " : SSL Cipher Check: $VERSION\n";
  print " :  - http://www.unspecific.com/ssl/\n";
  open (SSL, "$openssl version|") or die "$!\n";
  while (<SSL>) {
    print "Testing with $_";
  }
  close (SSL);
}

####
#
#  Testing port is running SSL at all
#
#
check_ssl($host, $port);

####
#
#  Testing for support of specific protocols as outlined above
#
#
print META "Testing for SSL/TLS Support\n" if ($DEBUG);
for my $protocol (sort keys %protocols) {
  print META "Testing $protocol ($protocols{$protocol}{'on'})\n" if ($DEBUG);
  open (SSL, "$openssl s_client $protocols{$protocol}{'on'} 2>&1 |") or die "ERROR: $!\n" ;
  while (<SSL>) {
    if (/unknown option/) {
      print "openssl s_client does not support $protocol\n" if ($opt_v);
      print META "openssl s_client does not support $protocol\n" if ($DEBUG);
      $protocols{$protocol}{'support'} = 'no';
      if ($protocol eq 'SSLv2' and $opt_v) {
        print "-- Using built in check for SSLv2\n";
      } elsif ($protocol eq 'SSLv3' and $opt_v) {
        print "-- Using built in check for SSLv3\n";
      }

      $protocol_count--;
    }
  }
  close(SSL);
}

# push @ciphers, 'EXPORT';

####
#
#  Testing for support of specific ciphers
#  As of openssl 1.0 the -v must be before the list of ciphers
#
#
print META "Getting cipher list from $openssl\n" if ($DEBUG);
# print META "echo | $openssl ciphers -v 'ALL:eNULL'\n" if ($DEBUG);
open (SSL, "$openssl ciphers -v 'ALL:eNULL'|") or die "$!\n";
while (<SSL>) {
  chomp;
  my @cipher = split(' ');
  my $cipher_name = $cipher[0];
  # if ($DEBUG) { print META "Cipher: $cipher_name\n" . Dumper(@cipher) }
  for my $cipher_data (@cipher) {
    if ($cipher_data eq 'Enc=None') {
      $ciphers{$cipher_name} = 'None';
    } elsif ($cipher_data =~ /^Enc=.+\((\d+)\)$/) {
      $ciphers{$cipher_name} = "$1 bits";
    }
    push @ciphers, $cipher_name;
  }
}
close (SSL);
# print META "echo | $openssl ciphers -v 'ALL:aNULL'\n" if ($DEBUG);
open (SSL, "$openssl ciphers -v 'ALL:aNULL'|") or die "$!\n";
while (<SSL>) {
  chomp;
  my @cipher = split(' ');
  my $cipher_name = $cipher[0];
  # if ($DEBUG) { print META "Cipher: $cipher_name\n" . Dumper(@cipher) }
  for my $cipher_data (@cipher) {
    if ($cipher_data eq 'Enc=None') {
      $ciphers{$cipher_name} = 'None';
    } elsif ($cipher_data =~ /^Enc=.+\((\d+)\)$/) {
      $ciphers{$cipher_name} = "$1 bits";
    }
    push @ciphers, $cipher_name;
  }
}
close (SSL);

####
#
#  Testing website/IP starts here
#
#
my %saw;
my $pci = 0;
my %results;
####
#
#  Testing SSLv2 and SSLv3 via socket
#
#
if ($protocols{'SSLv2'}{'support'} eq 'no') {
  $results{'SSLv2'}{'DEFAULT'}{'enabled'} = &check_sslv2($host, $port);
}
if ($protocols{'SSLv3'}{'support'} eq 'no') {
  $results{'SSLv3'}{'DEFAULT'}{'enabled'} = &check_sslv3($host, $port);
}
# remove duplicate ciphers
@ciphers = grep(!$saw{$_}++, @ciphers);

if ($opt_v) {
  my $ts = $#ciphers * $protocol_count;
  print "Running a total of $ts scans";
  print " across $protocol_count protocols";
  print " with $#ciphers ciphers\n";
}
print META join(", ", @ciphers) . "\n" if ($DEBUG);
# print META "\n\n" . Dumper(\%ciphers) if ($DEBUG);
# print META "\n\n" . Dumper(\@ciphers) if ($DEBUG);

####
#
#  Testing for default (let the server decide what to use)
#
#
if ($opt_v) {
  my $grab_cert = "FALSE";
  print "Getting default Cipher/Proto\n" if ($DEBUG);
  print META "echo | $openssl s_client $options -connect $host:$port\n" if ($DEBUG);
  open (SSL, "echo | $openssl s_client $options -connect $host:$port 2>&1 |");
  while (<SSL>) {
    chomp;
    print META "`-DEF: $_\n" if ($DEBUG);
    if (/^-----BEGIN CERTIFICATE-----$/) {
      $results{'certificate'} = "$_\n";
      $grab_cert = "TRUE";
      next;
    } elsif (/^-----END CERTIFICATE-----$/) {
      $results{'certificate'} .= "$_\n";
      $grab_cert = "FALSE";
      next;
    } elsif ($grab_cert eq "TRUE") {
      $results{'certificate'} .= "$_\n";
      next;
    }
    if (/^\d+:error:/) {
      print META "`-DEF: ERROR\n" if ($DEBUG);
      my ($pid, $err, $unk, $routine, $func,
        $msg, $file, $lineno, $err_msg) = split(':');
      if ($err_msg eq 'Name or service not known') {
        die "ERROR: $err_msg\nPlease check hostname ($host)\n\n";
      } elsif ($msg eq 'Connection refused') {
        die "ERROR: $msg\nERROR: $host:$port\n\n";
      }
    } elsif (/^    Protocol  : (.+)$/) {
      $results{'default_proto'} = $1;
    } elsif (/^    Cipher    : (.+)$/) {
      $results{'default_cipher'} = $1;
    } elsif (/^Secure Renegotiation/) {
      $results{'renegoation'} = $_;
    }
  }
  close(SSL);
  if ($opt_v and $results{'certificate'}) {
    &parse_cert($results{'certificate'});
  }
}
print META Dumper(\%results) if ($DEBUG);

####
#
#  Testing each cipher for each protocol supported by openssl
#
#
print META "\n" if ($DEBUG);
my $counter;
for my $cipher (sort @ciphers) {
  next if ($cipher =~ /^\s*$/);
  # print "Checking $cipher\n" if ($DEBUG);
  print META '-' x 72 . "\n" if ($DEBUG);
  print META localtime() . " $cipher\n" if ($DEBUG);
  my @cert;

  for my $protocol (sort keys %protocols) {
    my $command = "$openssl s_client";
    $command .= " $protocols{$protocol}{'on'}";
    $command .= " $options -cipher $cipher -connect $host:$port";
    next if ($protocols{$protocol}{'support'} eq 'no');
    # print "Checking $protocol - $cipher\n" if ($DEBUG);
    print META '-' x 72 . "\n" if ($DEBUG);
    print META "Checking $protocol - $cipher\n" if ($DEBUG);
    if ($opt_v and !$DEBUG) {
      $counter++;
      print ".";
      if ($counter % 50 == 0) {
        print ":$counter\n"
      }
    }
    print META "Running $command\n" if ($DEBUG);
    open (SSL, "echo | $command 2>&1 |");
    while (<SSL>) {
      chomp;
      print META "`-$protocol:$cipher: $_\n" if ($DEBUG);
      push(@cert, $_);
    }
    close(SSL);
    # examine what we received
    &check_cert($protocol, $cipher, @cert);
    print META "\n" if ($DEBUG);

    # clear cert between runs
    undef @cert;
  }
}
print META Dumper(\%results) if ($DEBUG);

print "\n\nResults:\n" if ($opt_v);
#
# Process %results and produce output
#
for my $proto (sort keys %protocols) {
  print META "RES: Processing $proto\n" if ($DEBUG);
  #print META Dumper(\%{$results{$proto}}) if ($DEBUG);
  for my $cipher (sort keys %{$results{$proto}}) {
    if (!defined($results{$proto}{$cipher}{'enabled'})){
      next;
    }
    #
    # if the Cipher is enabled for that protocol
    #
    if (
      defined($proto) and defined($cipher) and
	    $results{$proto}{$cipher}{'enabled'} eq 'TRUE'
	  ) {
      #
      # if the Cipher is weak
      #
      if ((grep(/^$cipher$/, @weak)
           or $proto eq 'SSLv3'
           or $proto eq 'SSLv2')) {
          if (!$opt_s) {
            print "** $proto:$cipher - ENABLED - WEAK $ciphers{$cipher} **";
          }
          if ($opt_v and $results{$proto}{$cipher}{'err'}) {
            print "\n   ^Error" . $results{$proto}{$cipher}{'err'};
          }
          print "\n";
      } elsif (!$opt_w) {
        print "   $proto:$cipher - ENABLED - STRONG $ciphers{$cipher}";
        if ($opt_v and $results{$proto}{$cipher}{'err'}) {
          print "\n   ^Error" . $results{$proto}{$cipher}{'err'};
        }
        print "\n";
      }
      # Show all responses enabled or not
      #
    } elsif ($opt_a) {
      #
      # if the Cipher is weak
      #
      if (grep(/^$cipher$/, @weak)
          or $proto eq 'SSLv2'
          or $proto eq 'SSLv3') {
        if (!defined($ciphers{$cipher})) {
          print "   $proto:$cipher - DISABLED or UNSUPPORTED - WEAK";
        } else {
          print "   $proto:$cipher - DISABLED - WEAK $ciphers{$cipher}  *";
        }
        if ($opt_v and $results{$proto}{$cipher}{'err'}) {
          print $results{$proto}{$cipher}{'err'};
        }
        print "\n";
      } else {
        print "   $proto:$cipher - DISABLED - STRONG $ciphers{$cipher}  *";
        if ($opt_v and $results{$proto}{$cipher}{'err'}) {
          print $results{$proto}{$cipher}{'err'};
        }
        print "\n";
      }
    }
  }
  if ($opt_v and $results{$proto}{'err'}) {
    for my $err (keys %{$results{$proto}{'error'}}) {
      print "   Error $err Encountered: " . $results{$proto}{'error'}{$err} . "\n";
    }
  }
  # print "\n";
}
if ($results{'key_size'} < 2048) {
  print "Key Size is below recommended 2048 ";
  print "Currently using " . $results{'key_size'} . "bits\n";
}
if ($results{'signature'}) {
  print "\nSigning Algorithm: $results{'signature'}\n";
  if ($results{'signature'} =~ /sha1/ or $results{'signature'} =~ /md5/) {
    print "  The Signing Algorithm has known issues.\n"
  }
}
if (defined($results{'SSLv2'}{'DEFAULT'}{'enabled'}) and
    $results{'SSLv2'}{'DEFAULT'}{'enabled'} eq 'TRUE') {
  print "***SSLv2 Enabled - Just BROKEN\n\n"
}
if (defined($results{'SSLv3'}{'DEFAULT'}{'enabled'}) and
    $results{'SSLv3'}{'DEFAULT'}{'enabled'} eq 'TRUE') {
  print "***SSLv3 Enabled - Vulnerbale to POODLE\n\n"
}
if ($opt_v) {
  print "\nDefault protocol\\cipher (for openssl client):\n";
  print "  $results{'default_proto'}\\$results{'default_cipher'}\n";
  print "  $results{'renegoation'}\n";
  print "\n";
  print "Certificate Details:\n";
  if ($results{'key_size'} < 2048) {
    print "*WARNING* Weak";
  }
  print "  Key Size: " . $results{'key_size'} . "bits\n";
  print "  Issuer: \n";
  for my $entry (keys %{$results{'issuer'}}) {
    #print "--------- $entry\n";
    if (defined($names{$entry}) and defined($results{'issuer'}{$entry})) {
      print "\t" . $names{$entry} . " : " . $results{'issuer'}{$entry} . "\n";
    }
  }
  print "  Subject: \n";
  for my $entry (keys %{$results{'subject'}}) {
    #print "--------- $entry\n";
    if (defined($names{$entry}) and defined($results{'subject'}{$entry})) {
      print "\t" . $names{$entry} . " : " . $results{'subject'}{$entry} . "\n";
    }
  }
  if ($host ne $results{'subject'}{'CN'}){
    print "\n**Tested name ($host) does not match Common Name ($results{'subject'}{'CN'})\n"
  }
  print "\n";
  if ($opt_g) {
    if (-e $gnutls) {
      open (TLS, "$gnutls -p $port $host |") or print "ERROR: $gnutls $!\n";
      while (<TLS>) {
        print META "`-GNUTLS-$_" if ($DEBUG);
#        if ( /^Checking/ and
#           ( $_ !~ /for certificate informaiton/ or
#             $_ !~ /RSA\-export ciphersuite info/ or
#             $_ !~ /ephemeral Diffie Hellman group info/ or
#             $_ !~ /for trusted CAs/ )
#         ) {
          print $_;
#        }
      }
      close(TLS);
    } else {
      print "ERROR: Unable to find $gnutls.\n";
      print "  Please install the gnutls-devel/gnutls-bin (Debian based)\n";
      print "    or gnutls-utils (RedHat based) package\n";
    }
  }
  print "\n";
}
if ($results{'expired'}) {
  print "WARNING: Expired Certificate - " . $results{'expired'} . "\n";
}
if ($results{'self_signed'}) {
  print "WARNING: Self Signed Certificate\n";
}
#
# show some stats
#
if ( defined($results{'weak'}) and
    $results{'weak'} > 0) {
  print "*WARNING* " . $results{'weak'} . " WEAK Ciphers Enabled.\n";
}
if ( defined($results{'poodle'}) and
    $results{'poodle'} > 0) {
  print "*WARNING* " . $results{'poodle'} . " Ciphers Enabled Vulnerable to POODLE.\n";
}
print "Total Ciphers Enabled: " . $results{'total'} . "\n";
my $time = time - $start;
print "Scan took $time secs to finish\n" if ($opt_v);
print META localtime() . " FINISHED\n" if ($DEBUG);
print localtime() . " FINISHED\n" if ($opt_v);

print "\n-- Check ssl_dump.log for debug info\n\n" if ($DEBUG);
# get the F out of here
close (META) if ($DEBUG);
exit;

sub check_cert {
  my ($proto, $cipher, @cert) = @_;
  print META "-" x 72 . "\n" if ($DEBUG);
  print META "Verifying $proto - $cipher results\n" if ($DEBUG);
  print "Verifying $proto - $cipher results\n" if ($DEBUG);
  for my $line (@cert) {
    print META "TEST: $line\n" if ($DEBUG);
    my $verify;
    #
    # Deal with errors
    #
    if ($line =~ /^\d+:error:/) {
      my ($pid, $err, $unk, $routine, $func,
        $msg, $file, $lineno, $err_msg) = split(':', $line);
      if ($err_msg eq 'Name or service not known') {
            die "ERROR: $err_msg\nPlease check hostname ($host)\n\n";
      } elsif ($msg eq 'Connection refused') {
            die "ERROR: $msg\nERROR: $host:$port\n\n";
      } elsif ($msg eq 'no ciphers available') {
        $results{$proto}{$cipher}{'enabled'} = 'FALSE';
        $results{$proto}{$cipher}{'err'} = 'no ciphers available';
        print META "TEST: No Cipher Available\n" if ($DEBUG);
        last;
      } elsif ($msg eq 'sslv3 alert handshake failure'
            or $msg eq 'ssl handshake failure') {
        $results{$proto}{$cipher}{'enabled'} = 'FALSE';
        $results{$proto}{$cipher}{'err'} = 'handshake failure';
        print META "TEST: Handshake Failure\n" if ($DEBUG);
        last;
      } elsif ($msg eq 'no cipher list') {
        $results{$proto}{$cipher}{'enabled'} = 'FALSE';
        $results{$proto}{$cipher}{'err'} = 'no cipher list';
        print META "TEST: No Cipher Available\n" if ($DEBUG);
        last;
      }
    #
    # Everything not an error
    #
    } elsif ($line =~ /^notAfter=(.+)$/ and !$results{'expired'}) {
      $results{'expired'} = $1;
      print META "TEST: CERT EXPIRED\n" if ($DEBUG);
    } elsif ($line =~ /^New, .*, Cipher is (.+)$/ and $cipher ne $1) {
      $results{$proto}{$cipher}{'enabled'} = 'FALSE';
      $results{$proto}{$cipher}{'err'} = 'cipher changed';
    } elsif ($line =~ /^(\s*)[Vv]erify return( code)?:/
        and !$results{$proto}{$cipher}{'enabled'}) {
      print META "  set-true: $proto $cipher TRUE\n" if ($DEBUG);
      $results{$proto}{$cipher}{'enabled'} = 'TRUE';
      $results{'total'}++;
      if (grep(/^$cipher$/, @weak)
          or $proto eq 'SSLv3'
          or $proto eq 'SSLv2') {
        $results{'weak'}++;
        if ($proto eq 'SSLv3') {
          $results{'poodle'}++;
        }
      }
    } elsif (
	      defined($proto) and defined($cipher) and
	      defined($results{$proto}{$cipher}{'enabled'}) and
	      $results{$proto}{$cipher}{'enabled'} eq 'TRUE' and
        $line =~ /^subject=?(.+)$/ and
        !$results{'subject'} ) {
      # Subject of Cert (who it is assign to)
      #
      my $subject = $1;
      # print META "\$proto = $proto, \$cipher = $cipher\n" if ($DEBUG);
      for my $entry (split('/', $subject)) {
        # print META "\$entry = $entry\n" if ($DEBUG);
        next if (!$entry);
        my ($key, $val) = split('=', $entry);
        if (defined($key) and defined($val)) {
          print META "SET Subject $key => $val\n" if ($DEBUG);
          $results{'subject'}{$key} = $val;
        }
      }
    } elsif (
	      defined($proto) and defined($cipher) and
	      defined($results{$proto}{$cipher}{'enabled'}) and
	      $results{$proto}{$cipher}{'enabled'} eq 'TRUE' and
        $line =~ /^issuer=(.+)$/ and
        !$results{'issuer'} ) {
      # Issuer
      #
      my $issuer = $1;
      for my $entry (split('/', $issuer)) {
        next if (!$entry);
        my ($key, $val) = split('=', $entry);
        if (defined($key) and defined($val)) {
          print META "SET Issuer $key => $val\n" if ($DEBUG);
          if ($key and $val and !$results{'issuer'}{$key}) {
            $results{'issuer'}{$key} = $val;
          }
        }
      }
    } elsif (
    	  defined($proto) and defined($cipher) and
    	  defined($results{$proto}{$cipher}{'enabled'}) and
	      $results{$proto}{$cipher}{'enabled'} eq 'TRUE' and
        $line =~ /^New, (.+), Cipher is (.+)$/ ) {
      if ($1 ne $proto or $2 ne $cipher) {
        $results{$proto}{$cipher}{'real_proto'} = $1;
        $results{$proto}{$cipher}{'real_cipher'} = $2;
        $results{$1}{$2}{'enabled'} = 'TRUE';
        $results{$1}{$2}{'err'} = "^Changed from $proto:$2";
      }
    } elsif (
	      defined($proto) and defined($cipher) and
      	defined($results{$proto}{$cipher}{'enabled'}) and
	      $results{$proto}{$cipher}{'enabled'} eq 'TRUE' and
        $line =~ /^Server public key is (\d+) bit$/ ) {
      $results{'key_size'} = $1;
    } elsif (
	      defined($proto) and defined($cipher) and
	      defined($results{$proto}{$cipher}{'enabled'}) and
	      $results{$proto}{$cipher}{'enabled'} eq 'TRUE' and
        $line =~ /^    Verify return code: (\d+ .+)$/) {
      $results{$proto}{$cipher}{'return_code'} = $1;
    } elsif (
        defined($proto) and defined($cipher) and
	      defined($results{$proto}{$cipher}{'enabled'}) and
	      $results{$proto}{$cipher}{'enabled'} eq 'TRUE' and
        $line =~ /^verify error:num=(\d+):(.+)$/) {
      my $num = $1;
      my $err = $2;
      $results{$proto}{'error'}{$num} = $err;
      if ($num == 18) {
        $results{'self_signed'} = 'TRUE';
      }
    } elsif (
	      defined($proto) and defined($cipher) and
	      defined($results{$proto}{$cipher}{'enabled'})
      ) {
      #print META "  ELSE case for $proto, $cipher and '" .
		  #      $results{$proto}{$cipher}{'enabled'}."'\n" if ($DEBUG);
    } else {
      #print META "  ELSE case for $proto, $cipher and 'not defined'\n" if ($DEBUG);
    }
  }
}

sub parse_cert {
  my ($cert) = @_;
  my $pwd = $ENV{'PWD'};
  my $certfile = "$pwd/.cert" . $$;
  open(CERT, '>', $certfile);
  print CERT $cert;
  close CERT;
  open (CERT, "$openssl x509 -in $certfile -text |") or die "ERROR $!\n";
  while (<CERT>) {
    # print $_;
    if (/\s+Signature Algorithm: (.+)/) {
      $results{'signature'} = $1;
    }

  }
  close(CERT);
  unlink($certfile);
}

sub check_sslv3 {
  my ($host, $port) = @_;
  my ($name,$aliases,$type,$len,@thisaddr) = gethostbyname($host);
  my ($a,$b,$c,$d) = unpack('C4',$thisaddr[0]);
  my $server_ip_address = "$a.$b.$c.$d";
  my $sslv3;
  my $data;
  $ciphers{'DEFAULT'} = 'DEFAULT';
  socket(SOCK,PF_INET,SOCK_STREAM,(getprotobyname('tcp'))[2])
     or die "Can't create a socket $!\n";
  connect( SOCK, pack_sockaddr_in($port, inet_aton($server_ip_address)))
     or die "Can't connect to port $port! \n";
  print META "SSLv3 check - Connected. Port $port open on $host($server_ip_address)\n" if ($DEBUG);
  send(SOCK, pack("H*", "160300007f0100007b030058519b8d96f54eaabf8919a46dc84abf9f27da764863acfb2f8929ba6b5e412100005400040005000a000d001000130016002f0030003100320033003500360037003800390041004400450066008400870088009600ffc002c003c004c005c007c008c009c00ac00cc00dc00ec00fc011c012c013c0140100"), 0);
  recv(SOCK,$data,4010,0); # or return("FALSE");
  if (defined($data) and length($data) > 1) {
    if (substr($data, 0, 3) eq pack("H*", "160300")
        and substr($data, 5, 1) eq pack("H*", "02")
        and substr($data, 9, 2) eq pack("H*", "0300")) {
      print META "SSLv3 enabled on $host\n" if ($DEBUG);
      $sslv3 = "TRUE";
    } elsif (substr($data, 0, 3) eq pack("H*", "150300")
        and substr($data, 5, 2) eq pack("H*", "0228")) {
      print META "\nSSLv3 not enabled on $host\n" if ($DEBUG);
      $sslv3 = "FALSE";
    } else {
      if ($DEBUG) {
        print META "SSLv3 check returned unknown response for protocol version: ";
        print META unpack("H*", $data);
        print "Not running SSLv3\n";
      } elsif ($opt_v) {
        print "Not running SSLv3\n";
      }
      print META "\nSSLv3 not enabled on $host\n" if ($DEBUG);
      $sslv3 = "FALSE";
    }
  }
  # print unpack("H*", $data);
  close (SOCK);
  return($sslv3);
}

sub check_sslv2 {
  my ($host, $port) = @_;
  my ($name,$aliases,$type,$len,@thisaddr) = gethostbyname($host);
  my ($a,$b,$c,$d) = unpack('C4',$thisaddr[0]);
  my $server_ip_address = "$a.$b.$c.$d";
  my $sslv2;
  my $data;
  $ciphers{'DEFAULT'} = 'DEFAULT';
  socket(SOCK,PF_INET,SOCK_STREAM,(getprotobyname('tcp'))[2])
     or die "Can't create a socket $!\n";
  connect( SOCK, pack_sockaddr_in($port, inet_aton($server_ip_address)))
     or die "Can't connect to port $port! \n";
  print META "SSLv2 check - Connected. Port $port open on $host($server_ip_address)\n" if ($DEBUG);
  send(SOCK, pack("H*", "80310100020018000000100700c00500800300800100800800800600400400800200807664752da798fec91292c12f348420c5"), 0);
  recv(SOCK,$data,4010,0); # or return();
  if (defined($data) and length($data) > 0) {
    if (substr($data, 2, 1) eq pack("H*", "04")
        and substr($data, 5, 2) eq pack("H*", "0002")) {
      print META "SSLv2 enabled on $host\n" if ($DEBUG);
      $sslv2 = "TRUE";
    } else {
      if ($DEBUG) {
        print META "SSLv2 check returned unknown response for protocol version: ";
        print META unpack("H*", substr($data, 9, 2));
        print "Not running SSLv2\n";
      } elsif ($opt_v) {
        print "Not running SSLv2\n";
      }
      print META "SSLv2 not enabled on $host\n" if ($DEBUG);
      $sslv2 = "FALSE";
    }
  }
  # print unpack("H*", $data);
  close (SOCK);
  return($sslv2);
}



sub check_ssl {
  my ($host, $port) = @_;
  my ($name,$aliases,$type,$len,@thisaddr) = gethostbyname($host);
  my ($a,$b,$c,$d) = unpack('C4',$thisaddr[0]);
  my $server_ip_address = "$a.$b.$c.$d";
  my $ssl;
  my $data;
  socket(SOCK,PF_INET,SOCK_STREAM,(getprotobyname('tcp'))[2])
     or die "Can't create a socket $!\n";
  connect( SOCK, pack_sockaddr_in($port, inet_aton($server_ip_address)))
     or die "Can't connect to port $port! \n";
  print META "Connected. Port $port open on $host($server_ip_address)\n" if ($DEBUG);
  # send TLS 1.2 handshake
  send(SOCK, pack("H*", "1603010200010001fc03032e7fdfe37b572b61bb05e2d5922c5270dcfbf60141cbc3fb864954cb4fa2d210209c4b522e63d59a907105c307221478c807f9ddcde0a977fd3a0ef3c131c3551800242a2ac02bc02fc02cc030cca9cca8cc14cc13c009c013c00ac014009c009d002f0035000a0100018fdada0000ff0100010000170000002300c0d4d0dd75f8b6c78841e803fc6048aa94bdc97f5ee6a34e7ba14910fa08dcba2e3bec821ba94b50e236a691e53cf7efc736bb9f515bda1ac80024e55fa7e8cffce4f8a293c159c1d9c5f69efb70a5f6ebe2e66c37683008641adae41999422432a37c9ea0192fe3058f9fb70260e4de260ae3f566c10393b6cc6db79e1c35a78a90470ee81c1f817a05284cf0dee8fffc6817e5c2738b4c442245c10be6d887b728c66c1cbb2ded4f814411fb44da988fe5dc4c01e672ff5e8ac354e1c6e2f9ba000d0012001006010603050105030401040302010203000500050100000000001200000010000e000c02683208687474702f312e3175500000000b00020100000a000a00087a7a001d00170018eaea000100001500680000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), 0);
  recv(SOCK,$data,4010,0); # or die "Error: $! $$";
  # did we get a tls 1.* response?
  if (substr($data, 0, 2) eq pack("H*", "1603")
      and substr($data, 5, 1) eq pack("H*", "02")) {
    print META "Appears SSL is enabled on $host:$port\n" if ($DEBUG);
  } else {
    if ($DEBUG) {
      print META "SSL check returned unknown response: ";
      print META length($data) . " bytes returned\n";
      print META "$data";
    }
    close (SOCK);
    die "SSL is not running on $host:$port, please select another target\n";
  }
  # print unpack("H*", $data);
  close (SOCK);
  return();
}
