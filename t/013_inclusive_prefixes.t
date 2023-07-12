# -*- perl -*-

use Test::Lib;
use Test::XML::Sig;

my $xml = slurp_file('t/signed/inclusive.xml');
my $sig = XML::Sig->new();
my $ret = $sig->verify($xml);
ok($sig->verify($xml), "Successfully Verified XML with unused prefixes");
isa_ok($sig->signer_cert, 'Crypt::OpenSSL::X509', "Have the signer cert");

{
    my $xml = slurp_file('t/signed/inclusive2.xml');
    my $sig = XML::Sig->new();
    ok($sig->verify($xml), "Successfully Verified XML with unused prefixes");
    isa_ok($sig->signer_cert, 'Crypt::OpenSSL::X509', "Have the signer cert");
}

done_testing;
