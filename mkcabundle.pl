#!/usr/bin/perl -w
#
# Used to regenerate ca-bundle.crt from the Mozilla certdata.txt.
# Written by: Joe Orton and sent to modssl_users
#
# Run as ./mkcabundle.pl > ca-bundle.crt
#
#  new Locaiton: https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

# my $cvsroot = ':pserver:anonymous@cvs-mirror.mozilla.org:/cvsroot';
# my $certdata = 'mozilla/security/nss/lib/ckfw/builtins/certdata.txt';
# open(IN, "cvs -d $cvsroot co -p $certdata|")
#     || die "could not check out certdata.txt";
my $get_data = '';
my $certdata = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt";

if (-e "/usr/bin/curl") {
  $get_data = "/usr/bin/curl -s";
} elsif (-e "/usr/bin/wget") {
  $get_data = "/usr/bin/wget -q -O -";
} elsif (-e "/usr/bin/lynx") {
  $get_data = "/usr/bin/lynx -source";
}

open(IN, "$get_data $certdata|")
    || die "could not retrieve certdata.txt";

my $incert = 0;

print<<EOH;
# This is a bundle of X.509 certificates of public Certificate
# Authorities.  It was generated from the Mozilla root CA list.
#
# Source: $certdata
#
EOH

while (<IN>) {
    if (/^CKA_VALUE MULTILINE_OCTAL/) {
        $incert = 1;
        open(OUT, "|openssl x509 -text -inform DER -fingerprint")
            || die "could not pipe to openssl x509";
    } elsif (/^END/ && $incert) {
        close(OUT);
        $incert = 0;
        print "\n\n";
    } elsif ($incert) {
        my @bs = split(/\\/);
        foreach my $b (@bs) {
            chomp $b;
            printf(OUT "%c", oct($b)) unless $b eq '';
        }
    } elsif (/^CVS_ID.*Revision: ([^ ]*).*/) {
        print "# Generated from certdata.txt RCS revision $1\n#\n";
    }
}

