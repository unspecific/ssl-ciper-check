# ssl-cipher-check

<div class=mainbody>
<hr><center> <a href=#top>Top</a> | <a href=#download>Download</a> | <a href=#usage>Usage</a> | <a href=#changelog>ChangeLog</a> </center><hr>
A quick and easy way to verify what Ciphers are supported on a server.<br><br>

<b>ssl-cipher-check.pl</b><br>
I wanted a simple way to verify all the SSL ciphers a website could use 
(thanks PCI). I just needed something simple, not running a full blown 
vuln scanner and all the tools I could find (thanks THC) were windows 
based. So I wrote a very simple script… ssl-cipher-check.
<br><br>
<b>***UPDATE 2016-12-15 v2.0***</b> Major update.  Moved to GitHub. Rewrote a lot of logic to speed up and fix errors.
<br/>
<br/>

<b>***UPDATE 2015-02-25 v1.9***</b> Kurt at FreeBSD.org sent a patch to clean up my code to utilise 'use strict' and 'use warnings'  
<br/>I appreciate it, as I am lazy<br/> 
<br/>
<b>***UPDATE 2014-10-16 v1.8***</b> Added TLS1.1 &amp; 1.2 support and added SSLv3 as weak, plus POODLE identification.<br/> 
Added -g flag to run glutls debug util seperately.<br>
<br/>
<b>***NOTE***</b> Steve Zenone wrote a good article on his <a href=http://www.transindiaacquisition.com/>blog</a> about how and why of this stuff...  
<a href=http://blog.zenone.org/2009/03/pci-compliance-disable-sslv2-and-weak.html>PCI Compliance - Disable SSLv2 and Weak Ciphers</a>
 is a good read and the tool and his article compliment each other well.
<br><br>
<b>***UPDATE 2012-03-07 v1.7***</b> markus.theissinger (of .de) pointed out a flaw and gave me a fix.<br>
There were some different output in some versions of OpenSSL so the patch dealt with that to make the results more accurate. Less false negatives.
<br><br>
<b>***UPDATE 2009-10-19 v1.6***</b> Steven Andrés (of <a href=http://SpecialOpsSecurity.com>Special Ops Security</a>) pointed out a flaw and gave me a fix.<br>
" For some cipher combinations, OpenSSL will return a "verify return" command but then later on fail with the "no cipher list" error. Since you check the former and not the latter, you false positive on these ciphers. "<br>
His patch has been applied and all is working well.
<br><br>
It starts by pulling a list of all the ciphers supported by the openssl 
client.  The number of checks it does is all dependant on the version and
configuration of OpenSSL on your machine.  It does include NULL checks as well.
On a CentOS server, this includes:<br>
ADH-AES256-SHA, DHE-RSA-AES256-SHA, DHE-DSS-AES256-SHA, AES256-SHA, ADH-AES128-SHA, DHE-RSA-AES128-SHA, 
DHE-DSS-AES128-SHA, AES128-SHA, DHE-DSS-RC4-SHA, EXP1024-DHE-DSS-RC4-SHA, EXP1024-RC4-SHA, EXP1024-DHE-D
SS-DES-CBC-SHA, EXP1024-DES-CBC-SHA, EXP1024-RC2-CBC-MD5, EXP1024-RC4-MD5, EXP-KRB5-RC4-MD5, EXP-KRB5-RC
2-CBC-MD5, EXP-KRB5-DES-CBC-MD5, EXP-KRB5-RC4-SHA, EXP-KRB5-RC2-CBC-SHA, EXP-KRB5-DES-CBC-SHA, KRB5-RC4-
MD5, KRB5-DES-CBC3-MD5, KRB5-DES-CBC-MD5, KRB5-RC4-SHA, KRB5-DES-CBC3-SHA, KRB5-DES-CBC-SHA, EDH-RSA-DES
-CBC3-SHA, EDH-RSA-DES-CBC-SHA, EXP-EDH-RSA-DES-CBC-SHA, EDH-DSS-DES-CBC3-SHA, EDH-DSS-DES-CBC-SHA, EXP-
EDH-DSS-DES-CBC-SHA, DES-CBC3-SHA, DES-CBC-SHA, EXP-DES-CBC-SHA, EXP-RC2-CBC-MD5, RC4-SHA, RC4-MD5, EXP-
RC4-MD5, ADH-DES-CBC3-SHA, ADH-DES-CBC-SHA, EXP-ADH-DES-CBC-SHA, ADH-RC4-MD5, EXP-ADH-RC4-MD5, RC4-64-MD
5, DES-CBC3-MD5, DES-CBC-MD5, RC2-CBC-MD5, NULL-SHA, NULL-MD5
<br><br>  
The script will connect first without specifying the Cipher or protocol.
This will allow us to determine the default Cipher/Proto combination
used  for the server.
<br><br>
Then the script tries to connect to the server, on the specified port or 
443 if a port is not given, and record the output to a log file called 
ssl_dump.log.  Because all of this happens before any protocol specific 
commands, this will work with HTTP, POP, IMAP or any SSL enable protocol.
<br><br>
Below you will find a sample ssl_dump.log, the script itself and a script 
to grab a list of CA certs for verifying the SSL cert signature. Below
that is some sample output.  
<br><br>
I also did a presentation at <a href=http://dc214.org/>DC214</a> on 
March 11, 2009, explaining what SSL is and the tool.  Most of the 
presentation was live demos, so the <a href=http://dc214.org/.go/presentations#mar2009>slides</a>
are very simple.
<br><br>
As always feedback is welcome.

<br><br>
<b>mkcabundle.pl</b><br>
126 CA supported.  mkcabundle.pl was writen by Joe Orton and sent to 
modssl_users.  The script logs into the Mozilla anonymous CVS server 
(so cvs must be installed) and downloads the lastest list of CA distributed 
with Firefox and other Mozilla products.
<pre> perl ./mkcabundle.pl > ca-bundle.crt </pre>
<a name=download><hr><center> <a href=#top>Top</a> | <a href=#download>Download</a> | <a href=#usage>Usage</a> | <a href=#changelog>ChangeLog</a> </center><hr>
<h3>Download:</h3>
<a href=ssl-cipher-check.pl>ssl-cipher-check.pl</a> - The script itself.<br>
<a href=mkcabundle.pl>mkcabundle.pl</a> - The CA bundle creation script.<br>
<a href=ssl_dump.log>ssl_dump.log</a> - Sample dump log<br>
<a name=usage><hr><center> <a href=#top>Top</a> | <a href=#download>Download</a> | <a href=#usage>Usage</a> | <a href=#changelog>ChangeLog</a> </center><hr>
<h3>Usage:</h3>
<pre>
$ perl ./ssl-cipher-check.pl 
 : SSL Cipher Check: 1.2
 : written by Lee 'MadHat' Heath (at) Unspecific.com
Usage:
  ./ssl-cipher-check.pl [ -dvwas ] <host> [<port>]
default port is 443
-d  Add debug info (show it all, lots of stuff)
-v  Verbose.  Show more info about what is found
-w  Show only weak ciphers enabled.
-a  Show all ciphers, enabled or not
-s  Show only the STRONG ciphers enabled.
</pre>

<br><hr>
<h3>Default Output:</h3>
<pre>
$ perl ./ssl-cipher-check.pl mail.yahoo.com
Testing mail.yahoo.com:443
   SSLv3:RC4-MD5 - ENABLED - STRONG 128 bits 
   SSLv3:DES-CBC3-SHA - ENABLED - STRONG 168 bits 
   SSLv3:RC4-SHA - ENABLED - STRONG 128 bits 
** SSLv3:DES-CBC-SHA - ENABLED - WEAK 56 bits **
** SSLv3:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** SSLv3:EXP-DES-CBC-SHA - ENABLED - WEAK 40 bits **
** SSLv3:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
   SSLv3:AES128-SHA - ENABLED - STRONG 128 bits 
   SSLv3:AES256-SHA - ENABLED - STRONG 256 bits 

   TLSv1:RC4-MD5 - ENABLED - STRONG 128 bits 
   TLSv1:DES-CBC3-SHA - ENABLED - STRONG 168 bits 
   TLSv1:RC4-SHA - ENABLED - STRONG 128 bits 
** TLSv1:DES-CBC-SHA - ENABLED - WEAK 56 bits **
** TLSv1:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** TLSv1:EXP-DES-CBC-SHA - ENABLED - WEAK 40 bits **
** TLSv1:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
   TLSv1:AES128-SHA - ENABLED - STRONG 128 bits 
   TLSv1:AES256-SHA - ENABLED - STRONG 256 bits 

** SSLv2:RC4-MD5 - ENABLED - WEAK 128 bits **
** SSLv2:RC2-CBC-MD5 - ENABLED - WEAK 128 bits **
** SSLv2:DES-CBC-MD5 - ENABLED - WEAK 56 bits **
** SSLv2:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** SSLv2:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
** SSLv2:DES-CBC3-MD5 - ENABLED - WEAK 168 bits **

*WARNING* 14 WEAK Ciphers Enabled.
Total Ciphers Enabled: 24
</pre>

<br><hr>
<h3>Verbose Output:</h3>
<pre>
$ perl ./ssl-cipher-check.pl -v usa.visa.com
Mon Mar 16 13:11:33 2009 START
Testing usa.visa.com:443
Testing with OpenSSL 0.9.8g 19 Oct 2007
Running a total of 105 scans
............................................................................................................

   SSLv3:RC4-MD5 - ENABLED - STRONG 128 bits 
   SSLv3:DES-CBC3-SHA - ENABLED - STRONG 168 bits 
   SSLv3:RC4-SHA - ENABLED - STRONG 128 bits 
** SSLv3:DES-CBC-SHA - ENABLED - WEAK 56 bits **
** SSLv3:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** SSLv3:EXP-DES-CBC-SHA - ENABLED - WEAK 40 bits **
** SSLv3:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
   SSLv3:AES128-SHA - ENABLED - STRONG 128 bits 
   SSLv3:AES256-SHA - ENABLED - STRONG 256 bits 
  Error 20: unable to get local issuer certificate

   TLSv1:RC4-MD5 - ENABLED - STRONG 128 bits 
   TLSv1:DES-CBC3-SHA - ENABLED - STRONG 168 bits 
   TLSv1:RC4-SHA - ENABLED - STRONG 128 bits 
** TLSv1:DES-CBC-SHA - ENABLED - WEAK 56 bits **
** TLSv1:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** TLSv1:EXP-DES-CBC-SHA - ENABLED - WEAK 40 bits **
** TLSv1:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
   TLSv1:AES128-SHA - ENABLED - STRONG 128 bits 
   TLSv1:AES256-SHA - ENABLED - STRONG 256 bits 
  Error 20: unable to get local issuer certificate

** SSLv2:RC4-MD5 - ENABLED - WEAK 128 bits **
** SSLv2:RC2-CBC-MD5 - ENABLED - WEAK 128 bits **
** SSLv2:DES-CBC-MD5 - ENABLED - WEAK 56 bits **
** SSLv2:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** SSLv2:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
** SSLv2:DES-CBC3-MD5 - ENABLED - WEAK 168 bits **
  Error 27: certificate not trusted
  Error 21: unable to verify the first certificate
  Error 20: unable to get local issuer certificate

Default:
   TLSv1/SSLv3, Cipher is AES256-SHA

Certificate Details:
  Key Size: 1024bits
  Issuer: 
	Common Name (CN) : Akamai Subordinate CA 3
	Company (O) : Akamai Technologies Inc
	Country (C) : US
  Subject: 
	Common Name (CN) : usa.visa.com
	State (ST) : California
	Company (O) : Visa International Service Association
	Organizational Unit (OU) : Corporate intranet and internet
	Country (C) : US
	City (L) : Foster City

Checking for TLS 1.1 support... no
Checking fallback from TLS 1.1 to... TLS 1.0
Checking for TLS 1.0 support... yes
Checking for SSL 3.0 support... yes
Checking for version rollback bug in RSA PMS... no
Checking for version rollback bug in Client Hello... no
Checking whether we need to disable TLS 1.0... no
Checking whether the server ignores the RSA PMS version... no
Checking whether the server can accept Hello Extensions... yes
Checking whether the server can accept cipher suites not in SSL 3.0 spec... yes
Checking whether the server can accept a bogus TLS record version in the client hello... no
Checking whether the server understands TLS closure alerts... yes
Checking whether the server supports session resumption... yes
Checking for export-grade ciphersuite support... no
Checking for anonymous authentication support... no
Checking for anonymous Diffie Hellman prime size... N/A
Checking for ephemeral Diffie Hellman support... no
Checking for ephemeral Diffie Hellman prime size... N/A
Checking for AES cipher support (TLS extension)... yes
Checking for 3DES cipher support... yes
Checking for ARCFOUR 128 cipher support... yes
Checking for ARCFOUR 40 cipher support... no
Checking for MD5 MAC support... yes
Checking for SHA1 MAC support... yes
Checking for RIPEMD160 MAC support (TLS extension)... no
Checking for ZLIB compression support (TLS extension)... no
Checking for LZO compression support (GnuTLS extension)... no
Checking for max record size (TLS extension)... no
Checking for OpenPGP authentication support (TLS extension)... no

*WARNING* 14 WEAK Ciphers Enabled.
Total Ciphers Enabled: 24
Scan took 11 secs to finish
Mon Mar 16 13:11:44 2009 FINISHED
</pre>

<br><hr>
<h3>Verbose Output Expired, Self-Signed Cert on Port 995:</h3>
<pre>
$ perl ./ssl-cipher-check.pl -v unspecific.com 995
Mon Mar 16 13:29:53 2009 START
Testing unspecific.com:995
Testing with OpenSSL 0.9.8g 19 Oct 2007
Running a total of 105 scans
............................................................................................................

   SSLv3:RC4-MD5 - ENABLED - STRONG 128 bits 
   SSLv3:DES-CBC3-SHA - ENABLED - STRONG 168 bits 
   SSLv3:RC4-SHA - ENABLED - STRONG 128 bits 
** SSLv3:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** SSLv3:EXP-DES-CBC-SHA - ENABLED - WEAK 40 bits **
** SSLv3:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
   SSLv3:AES128-SHA - ENABLED - STRONG 128 bits 
   SSLv3:AES256-SHA - ENABLED - STRONG 256 bits 
  Error 18: self signed certificate
  Error 10: certificate has expired

   TLSv1:RC4-MD5 - ENABLED - STRONG 128 bits 
   TLSv1:DES-CBC3-SHA - ENABLED - STRONG 168 bits 
   TLSv1:RC4-SHA - ENABLED - STRONG 128 bits 
** TLSv1:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** TLSv1:EXP-DES-CBC-SHA - ENABLED - WEAK 40 bits **
** TLSv1:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
   TLSv1:AES128-SHA - ENABLED - STRONG 128 bits 
   TLSv1:AES256-SHA - ENABLED - STRONG 256 bits 
  Error 18: self signed certificate
  Error 10: certificate has expired

** SSLv2:RC4-MD5 - ENABLED - WEAK 128 bits **
** SSLv2:RC2-CBC-MD5 - ENABLED - WEAK 128 bits **
** SSLv2:EXP-RC4-MD5 - ENABLED - WEAK 40 bits **
** SSLv2:EXP-RC2-CBC-MD5 - ENABLED - WEAK 40 bits **
** SSLv2:DES-CBC3-MD5 - ENABLED - WEAK 168 bits **
  Error 18: self signed certificate
  Error 10: certificate has expired

Default:
   TLSv1/SSLv3, Cipher is AES256-SHA

Certificate Details:
  Key Size: 1024bits
  Issuer: 
	Common Name (CN) : mail2.unspecific.com
	Company (O) : Unspecific
	State (ST) : Texas
	Organizational Unit (OU) : Security
	Contact : madhat@unspecific.com
	Country (C) : US
	City (L) : Dallas
  Subject: 
	Common Name (CN) : mail2.unspecific.com
	Company (O) : Unspecific
	State (ST) : Texas
	Organizational Unit (OU) : Security
	Contact : madhat@unspecific.com
	Country (C) : US
	City (L) : Dallas


WARNING: Expired Certificate - Jun 21 06:17:31 2008 GMT
WARNING: Self Signed Certificate
*WARNING* 12 WEAK Ciphers Enabled.
Total Ciphers Enabled: 22
Scan took 13 secs to finish
Mon Mar 16 13:30:06 2009 FINISHED
</pre>
<a name=usage><hr><center> <a href=#top>Top</a> | <a href=#download>Download</a> | <a href=#usage>Usage</a> | <a href=#changelog>ChangeLog</a> </center><hr>
<h3>CHANGELOG:</h3>
<pre>
<!--#include virtual="CHANGELOG"-->
</pre>
</div>

