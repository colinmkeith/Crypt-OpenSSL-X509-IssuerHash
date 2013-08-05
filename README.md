Crypt-OpenSSL-X509-IssuerHash v0.05
===================================

NAME
====

Crypt::OpenSSL::X509::IssuerHash - A Perl module to access an SSL certificate's issuer hash

DESCRIPTION
===========

This module provides access to the hash of the issuer Common Name (CN) in an X509 certificate.
    
Accessing this value means that you know the ID of the issuer, which allows you to locate the
certificate that was used to sign a certificate and upwards until you have built up a chain of
SSL Certificaates. This is useful when you need to build a certificate bundle for a web server
like Apache (See [SSLCertificateChainFile](http://httpd.apache.org/docs/current/mod/mod_ssl.html#sslcertificatechainfile))


LICENSE
=======

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)

COPYRIGHT
=========

This software is Copyright (c) 2013 by Colin Keith.


[![Build Status](https://travis-ci.org/colinmkeith/Crypt-OpenSSL-X509-IssuerHash.png?branch=master)](https://travis-ci.org/colinmkeith/Crypt-OpenSSL-X509-IssuerHash)
