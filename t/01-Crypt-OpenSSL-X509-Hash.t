# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

use Test::More;

BEGIN { plan tests => 8 }
use blib;
use Crypt::OpenSSL::X509::IssuerHash
    qw(:hash :name :modulus :info get_certhash_error);
ok(1);    # If we made it this far, we're ok.

my $crt = 't/test.crt';
my $csr = 't/test.csr';
my $key = 't/test.key';

my $ihash = get_issuer_hash($crt)  || die get_certhash_error();
my $shash = get_subject_hash($crt) || die get_certhash_error();

diag('start');
diag("Subject hash (my ID): $shash");
diag("Issuer hash (issuer ID): $ihash");

ok(1);

diag('about to check key modulus');
my $kmod = get_modulus( $key, 0 ) || fail( get_certhash_error() );
diag('about to check cert modulus');
my $cmod = get_modulus( $crt, 1 ) || fail( get_certhash_error() );
diag('about to check csr modulus');
my $smod = get_modulus( $csr, 2 ) || fail( get_certhash_error() );

diag("key modulus: $kmod");
diag("csr modulus: $smod");
diag("crt modulus: $cmod");

diag('2. Checking is_key_cert_pair()');
ok( is_key_cert_pair( $key, $crt ) );

diag('3. Checking if key modulus = csr modulus');
ok( $kmod eq $smod );

diag( "4. Getting issuer name:\n" . get_issuer_name($crt) );
ok(1);

diag( "5. Getting subject name:\n", get_subject_name($crt) );
ok(1);

my $r = check_cert_validity($crt);
diag( "6. Checking if Cert usable now?\n",
    ( 'Not yet valid', 'Valid', 'Expired' )[ $r + 1 ] );
ok(1);

diag( "7. Checking Before/After\n",
    map { localtime($_) . "\n" } get_cert_validity($crt) );
ok(1);

