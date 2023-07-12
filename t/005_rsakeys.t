# -*- perl -*-

use Test::Lib;
use Test::XML::Sig;
use MIME::Base64 qw(decode_base64 encode_base64);

my $modulus = encode_base64(
    decode_base64(
        'rkqxhCTOB2XxFxCNWJt0bLWRQva6qOAPKiqlLfgJjG+YY2JaPtpO7WNV5oVqv9F21V/wgOkcQTZZQQQl/L/eXlnFpJeSpF31dupLnzrBU29qWjedNCkj+y01sprJG+c++2d2jV8Qccp55SklALtXYZ3K5OfILy4dFEqUyW0/Bk7Y/PdrAacAazumdNW2nw/ajbiXbUfm55QebQd/61emGettQBT9EUPOxMQrrtxHHxwyvrtsa9KyRPCamYEamOA0Al2Eya5dPWzEbndbVpRx1jz8Ec6ANk8wJHTkggJOUXWem7HL4x8v9hEQeaHEy5CwxKzodDpV2bA/Adr+NCYhsQ=='
    ),
    "\n"
);
my $exponent = 'AQAB';

my $sig = XML::Sig->new( { key => 't/rsa.private.key' } );
isa_ok( $sig, 'XML::Sig' );

isa_ok( $sig->{ key_obj }, 'Crypt::OpenSSL::RSA', 'Key object is valid' );

my $key_info = $sig->get_key_info;
my $xpc = get_xpath("$key_info", dsig => 'http://www.w3.org/2000/09/xmldsig#');

is($xpc->findvalue('/dsig:KeyInfo/dsig:KeyValue/dsig:RSAKeyValue/dsig:Modulus'), $modulus, "Modulus is correct");
is($xpc->findvalue('/dsig:KeyInfo/dsig:KeyValue/dsig:RSAKeyValue/dsig:Exponent'), $exponent, "Exponent is correct");

done_testing;
