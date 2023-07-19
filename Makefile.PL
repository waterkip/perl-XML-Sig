use strict;
use warnings;

use 5.010;

use ExtUtils::MakeMaker;

my %WriteMakefileArgs = (
  "ABSTRACT" => "A toolkit to help sign and verify XML Digital Signatures.",
  "AUTHOR" => "Byrne Reese <byrne\@cpan.org>, Timothy Legge <timlegge\@cpan.org>",
  "CONFIGURE_REQUIRES" => {
    "ExtUtils::MakeMaker" => 0
  },
  "DISTNAME" => "XML-Sig",
  "LICENSE" => "perl",
  "MIN_PERL_VERSION" => "5.010",
  "NAME" => "XML::Sig",
  "PREREQ_PM" => {
    "Carp" => 0,
    "Class::Accessor" => 0,
    "Crypt::Digest::RIPEMD160" => 0,
    "Crypt::Mac::HMAC" => 0,
    "Crypt::OpenSSL::Bignum" => 0,
    "Crypt::OpenSSL::DSA" => "0.20",
    "Crypt::OpenSSL::RSA" => 0,
    "Crypt::OpenSSL::X509" => 0,
    "Crypt::PK::ECC" => 0,
    "CryptX" => "0.036",
    "Digest::SHA" => 0,
    "Encode" => 0,
    "List::Util" => 0,
    "MIME::Base64" => 0,
    "URI" => 0,
    "XML::LibXML" => 0,
    "XML::LibXML::XPathContext" => 0
  },
  "TEST_REQUIRES" => {
    "Crypt::OpenSSL::Guess" => 0,
    "File::Spec::Functions" => 0,
    "File::Temp" => 0,
    "File::Which" => 0,
    "Import::Into" => 0,
    "Test::Deep" => 0,
    "Test::Exception" => 0,
    "Test::Lib" => 0,
    "Test::More" => 0,
    "URN::OASIS::SAML2" => 0
  },
  "VERSION" => "0.65",
  "test" => {
    "TESTS" => "t/*.t"
  }
);


my %FallbackPrereqs = (
  "Carp" => 0,
  "Class::Accessor" => 0,
  "Crypt::Digest::RIPEMD160" => 0,
  "Crypt::Mac::HMAC" => 0,
  "Crypt::OpenSSL::Bignum" => 0,
  "Crypt::OpenSSL::DSA" => "0.20",
  "Crypt::OpenSSL::Guess" => 0,
  "Crypt::OpenSSL::RSA" => 0,
  "Crypt::OpenSSL::X509" => 0,
  "Crypt::PK::ECC" => 0,
  "CryptX" => "0.036",
  "Digest::SHA" => 0,
  "Encode" => 0,
  "File::Spec::Functions" => 0,
  "File::Temp" => 0,
  "File::Which" => 0,
  "Import::Into" => 0,
  "List::Util" => 0,
  "MIME::Base64" => 0,
  "Test::Deep" => 0,
  "Test::Exception" => 0,
  "Test::Lib" => 0,
  "Test::More" => 0,
  "URI" => 0,
  "URN::OASIS::SAML2" => 0,
  "XML::LibXML" => 0,
  "XML::LibXML::XPathContext" => 0
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.63_03) } ) {
  delete $WriteMakefileArgs{TEST_REQUIRES};
  delete $WriteMakefileArgs{BUILD_REQUIRES};
  $WriteMakefileArgs{PREREQ_PM} = \%FallbackPrereqs;
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);
