package inc::Crypt::OpenSSL::X509::IssuerHash;
use Moose;
use File::Which;

extends 'Dist::Zilla::Plugin::MakeMaker::Awesome';

override _build_WriteMakefile_args => sub {
  my($LIBS, $INC);
  my $pkgConfig = which('pkg-config');
  my @sslDirs   = qw(
   /usr/local/openssl
   /usr/local/ssl
   /opt/ssl
   /apps/openssl/std
   /usr/sfw/
   C:\\OpenSSL
   /sslroot
  );

  if($pkgConfig && -x $pkgConfig) {
    $LIBS = `$pkgConfig openssl --libs`;
    $INC  = `$pkgConfig openssl --cflags`;
  } else {
    for my $sslDir (@sslDirs) {
      -d "$sslDir/include" && ($INC = "-I$sslDir/include");
      -d "$sslDir/lib"     && ($INC = "-L$sslDir/lib -lssl -lcrypto");
    }
  }

  $LIBS ||= '-L/usr/local/lib -L -L/usr/lib64 -L/lib64 -lssl -lcrypto';
  $INC  ||= '-I/usr/local/include';

  +{
    # Add LIBS => to WriteMakefile() args
    %{super()},
    LIBS => $LIBS,
    INC  => $INC,
  };
};

__PACKAGE__->meta->make_immutable;
