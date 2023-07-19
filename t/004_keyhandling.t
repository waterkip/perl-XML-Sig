# -*- perl -*-

use Test::Lib;
use Test::XML::Sig;

my $sig = XML::Sig->new({ key => 't/rsa.private.key' });
isa_ok($sig, 'XML::Sig');

throws_ok(
    sub { $sig = XML::Sig->new({ key => 'foobar' }) },
    qr/Could not load foobar: No such file or directory/,
    'new shoud die when it cannot find the private key'
);

throws_ok(
    sub { $sig = XML::Sig->new({ key => 'README' }) },
    qr/Could not detect type of key README/,
    'Unable to determine the type of key'
);

done_testing;
