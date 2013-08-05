package Crypt::OpenSSL::X509::IssuerHash;

use strict;
use warnings;
use utf8;

our $VERSION;
use base qw(Exporter DynaLoader);
use Time::Local;

our %EXPORT_TAGS = (
  'hash'    => [qw(get_issuer_hash get_subject_hash)],
  'name'    => [qw(get_issuer_name get_subject_name)],
  'info'    => [qw(get_cert_validity check_cert_validity)],
  'modulus' => [qw(get_modulus is_key_cert_pair)]);
our @EXPORT_OK = ('get_certhash_error', map { @{$_} } values(%EXPORT_TAGS));

# our @EXPORT = qw( );

# {{{ POD: NAME, SYNOPSIS, DESCRIPTION

=head1 NAME

Crypt::OpenSSL::X509::IssuerHash - Interface to Certificate Issuer and Subject Hashes

=head1 SYNOPSIS

  use Crypt::OpenSSL::X509::IssuerHash;
  my @chain = $cert;

  do {
    my $ihash = get_issuer_hash($cert);
    my $shash = get_issuer_hash($cert);

    $ihash eq $shash || last;

    $cert = "/usr/local/openssl/cert/".$ihash .'0';
    -f $cert || return "Certificate issuer with hash '$ihash' not found.\n";
    push(@chain, @cert);
  } while(1);

  # self-signed
  # if(@chain == 1){
  # }

  print qq/  SSLCertificateFile "$chain[0]"\n/;
  if(@chain == 2){
    print qq/  SSLCACertificateFile "$chain[1]"\n/;
    return;
  }

  if(@chain == 3){
    print qq/  SSLCACertificateFile "$chain[1]"\n/;
    print qq/  SSLCertificateChainFile "$chain[2]"\n/;
    return;
  }

  # Special case of multiple chain files. Should probably combine files
  # into one ChainFile, but right now we just die.
  die "Multiple intermediate CA's\n";

=head1 DESCRIPTION

This module returns the hash for the subject and issuer of an SSL Certificate.
This can be used to determine the issuer for a certificate and thus traverse
the issuer chain.

=head1 METHODS

The following methods are exported by this module:

=over 4

=item get_issuer_hash($cert)

ExportGroup: :hash

This function returns the hash for the Certificate issuer.

Returns: 8 digit hex value representing the hash for the issuer of the certificate.


=item get_subject_hash($cert)

ExportGroup: :hash

This function returns the hash for the Certificate issuer.

Returns: 8 digit hex value representing the hash for the issuer of the certificate.

=cut

# }}}

# This is all there is here. See the .xs for the code.. :)
bootstrap Crypt::OpenSSL::X509::IssuerHash $VERSION;

=item is_key_cert_pair($keyFile, $certFile)

Returns true if the keyfile and certificate have matching modulus.

=cut

sub is_key_cert_pair {
  my($keyFile, $certFile) = @_;
  my $kmod = get_modulus($keyFile)  || return 0;
  my $cmod = get_modulus($certFile) || return 0;
  return $kmod eq $cmod;
}

=item get_issuer_hash($certFile)

Returns the hash for the certificate issuer.

=cut

sub get_issuer_hash {
  my($certFile) = @_;
  return get_cert_hash($certFile, 0);
}

=pod

=encoding utf8

=item get_subject_hash($certFile)

Returns the hash for the certificate subject.

=cut

sub get_subject_hash {
  my($certFile) = @_;
  return get_cert_hash($certFile, 1);
}

=item get_issuer_name($certFile)

Returns the CN of the issuer

=cut

sub get_issuer_name {
  my($certFile) = @_;
  return get_cert_name($certFile, 0);
}

=item get_subject_name($certFile)

Returns the CN for the certificate subject.

=cut

sub get_subject_name {
  my($certFile) = @_;
  return get_cert_name($certFile, 1);
}

=item get_cert_validity($certFile, [$type])

Fetches the start and end dates of the certificate as a unix timestamp Return
value is an array if no type is requested, if type is 1 the return value is a
unix timestamp for the end time stamp, otherwise the return value is a unix
timestamp for the start time stamp.

=cut

sub get_cert_validity {
  my($certFile, $type) = @_;
  my($bef,      $aft)  = get_cert_validityint($certFile);
  ## no critic (RegularExpressions::ProhibitComplexRegexes)
  my $dateRE =
   qr/^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$/x;
  ## use critic
  my(@aft, @bef);

  if($aft =~ $dateRE) {
    @aft = ($6, $5, $4, $3, $2 - 1, '20' . $1);
  }

  if($bef =~ $dateRE) {
    @bef = ($6, $5, $4, $3, $2 - 1, '20' . $1);
  }

  if(!defined($type)) {
    return (Time::Local::timegm(@bef), Time::Local::timegm(@aft));
  }
  if($type) {
    wantarray() && return @aft;
    return Time::Local::timegm(@aft);
  } else {
    wantarray() && return @bef;
    return Time::Local::timegm(@bef);
  }
}

=item get_cert_website($certFile)

Returns the Common Name (CN) portion of the certificate name.

=cut

sub get_cert_website {
  my($certFile) = @_;
  my $sub = get_cert_name($certFile, 1) || return '';
  $sub =~ m/CN=([a-z0-9.\*-]+)/x && return $1;
  return '';
}

1;

# {{{ POD: AUTHOR, TODO, SEE ALSO

=back

=head1 AUTHOR

Colin Keith <ckeith@cpan.org>

=head1 NOTES

 * First time writing an XS so it may leak memory.

=cut

# }}}

# /* vim600: set foldmethod=marker: */
