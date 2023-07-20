use strict;
use warnings;

package XML::Sig;
use Smart::Comments;

# VERSION


# ABSTRACT: XML::Sig - A toolkit to help sign and verify XML Digital Signatures

=head1 NAME

XML::Sig - A toolkit to help sign and verify XML Digital Signatures.

=head1 SYNOPSIS

   my $xml = '<foo ID="abc">123</foo>';
   my $signer = XML::Sig->new({
     key => 'path/to/private.key',
   });

   # create a signature
   my $signed = $signer->sign($xml);
   print "Signed XML: $signed\n";

   # verify a signature
   $signer->verify($signed)
     or die "Signature Invalid.";
   print "Signature valid.\n";

=head1 DESCRIPTION

This perl module provides two primary capabilities: given an XML string, create
and insert digital signatures, or if one is already present in the string verify
it -- all in accordance with the W3C standard governing XML signatures.

=cut

# use 'our' on v5.6.0
use vars qw($VERSION @EXPORT_OK %EXPORT_TAGS $DEBUG);

$DEBUG = 0;

use base qw(Class::Accessor);
XML::Sig->mk_accessors(qw(key));

=head1 PREREQUISITES

=over

=item * L<Digest::SHA>

=item * L<XML::LibXML>

=item * L<MIME::Base64>

=item * L<Crypt::OpenSSL::X509>

=item * L<Crypt::OpenSSL::Bignum>

=item * L<Crypt::OpenSSL::RSA>

=item * L<Crypt::OpenSSL::DSA>

=item * L<Crypt::PK::ECC>

=back

=cut

use feature qw(state);

use Carp;
use Crypt::Digest::RIPEMD160 qw/ripemd160/;
use Crypt::OpenSSL::Bignum;
use Crypt::OpenSSL::DSA;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use Crypt::PK::ECC;
use CryptX;
use Digest::SHA
    qw(sha1 sha224 sha256 sha384 sha512 hmac_sha1 hmac_sha256 hmac_sha384 hmac_sha512);
use Encode qw(encode_utf8);
use List::Util qw(any none);
use MIME::Base64;
use XML::LibXML;
use XML::LibXML::XPathContext;

=head1 USAGE

=head2 SUPPORTED ALGORITHMS & TRANSFORMS

This module supports the following signature methods:

=over

=item * DSA

=item * RSA

=item * RSA encoded as x509

=item * ECDSA

=item * ECDSA encoded as x509

=item * HMAC

=back

This module supports the following canonicalization methods and transforms:

=over

=item * Enveloped Signature

=item * REC-xml-c14n-20010315#

=item * REC-xml-c14n-20010315#WithComments

=item * REC-xml-c14n11-20080502

=item * REC-xml-c14n11-20080502#WithComments

=item * xml-exc-c14n#

=item * xml-exc-c14n#WithComments

=back

=cut

use constant TRANSFORM_ENV_SIG =>
    'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
use constant TRANSFORM_C14N =>
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
use constant TRANSFORM_C14N_COMMENTS =>
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
use constant TRANSFORM_C14N_V1_1 =>
    'http://www.w3.org/TR/2008/REC-xml-c14n11-20080502';
use constant TRANSFORM_C14N_V1_1_COMMENTS =>
    'http://www.w3.org/TR/2008/REC-xml-c14n11-20080502#WithComments';
use constant TRANSFORM_EXC_C14N => 'http://www.w3.org/2001/10/xml-exc-c14n#';
use constant TRANSFORM_EXC_C14N_COMMENTS =>
    'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

=head2 OPTIONS

Each of the following options are also accessors on the main
XML::Sig object. TODO Not strictly correct rewrite

=over

=item B<key>

The path to a file containing the contents of a private key. This option
is used only when generating signatures.

=item B<cert>

The path to a file containing a PEM-formatted X509 certificate. This
option is used only when generating signatures with the "x509"
option. This certificate will be embedded in the signed document, and
should match the private key used for the signature.

=item B<cert_text>

A string containing a PEM-formatted X509 certificate. This
option is used only when generating signatures with the "x509"
option. This certificate will be embedded in the signed document, and
should match the private key used for the signature.

=item B<x509>

Takes a true (1) or false (0) value and indicates how you want the
signature to be encoded. When true, the X509 certificate supplied will
be encoded in the signature. Otherwise the native encoding format for
RSA, DSA and ECDSA will be used.

=item B<sig_hash>

Passing sig_hash to new allows you to specify the SignatureMethod
hashing algorithm used when signing the SignedInfo.  RSA and ECDSA
supports the hashes specified sha1, sha224, sha256, sha384 and sha512

DSA supports only sha1 and sha256 (but you really should not sign
anything with DSA anyway).  This is over-ridden by the key's signature
size which is related to the key size.  1024-bit keys require sha1,
2048-bit and 3072-bit keys require sha256.

=item B<digest_hash>

Passing digest_hash to new allows you to specify the DigestMethod
hashing algorithm used when calculating the hash of the XML being
signed.  Supported hashes can be specified sha1, sha224, sha256,
sha384, sha512, ripemd160

=item B<hmac_key>

Base64 encoded hmac_key

=item B<key_name>

The name of the key that should be referenced.  In the case of
xmlsec the --keys-file (ex. t/xmlsec-keys.xml) holds keys with a
KeyName that is referenced by this name.

=item B<no_xml_declaration>

Some applications such as Net::SAML2 expect to sign a fragment of the
full XML document so is this is true (1) it will not include the
XML Declaration at the beginning of the signed XML.  False (0) or
undefined returns an XML document starting with the XML Declaration.

=back

The following options act similar to C<< xmlsec --id-attr:ID
<node-namespace-uri>:<name> >>

=over

=item B<ns>

A HashRef to namespaces you want to define to select the correct attribute ID on

=item B<id_attr>

The xpath string you want to sign your XML message on.

=back

=head2 METHODS

=head3 B<new(...)>

Constructor; see OPTIONS above.

=cut

sub new {
    my $class  = shift;
    my $params = shift;
    my $self   = {};

    bless $self, $class;

    foreach my $prop (qw/key cert cert_text ns id_attr/) {
        $self->{$prop} = $params->{$prop} if exists $params->{$prop};
    }

    $self->{x509} = exists $params->{x509} ? 1 : 0;

    my @options = grep { /^(?:cert|cert_text)$/ } keys %$params;
    croak
        "You can only supply one argument for cert or cert_text"
        if @options > 1;

    $self->{key_name} = $params->{key_name} if exists $params->{key_name};

    foreach (qw(key cert cert_text hmac_key)) {
        next unless exists $params->{$_};
        my $method = "_load_${_}";
        $self->$method($params->{$_});
    }

    $params->{sig_hash} //= 'sha256';
    if (none { $_ eq $params->{sig_hash} }
        qw(sha1 sha224 sha256 sha384 sha512 ripemd160'))
    {
        croak "Unknown signature hash option chose: $params->{sig_hash}";
    }
    $self->{sig_hash} = $params->{sig_hash};

    $params->{digest_hash} //= 'sha256';
    if (none { $_ eq $params->{digest_hash} }
        qw(sha1 sha224 sha256 sha384 sha512 ripemd160'))
    {
        croak "Unknown digest hash chosen: $params->{digest_hash}";
    }
    $self->{digest_hash} = $params->{digest_hash};

    if (($self->{key_type} //'') eq 'dsa') {
        my $sig_size = $self->{key_obj}->get_sig_size();
        # The key size dictates the sig size
        $self->{sig_hash} = $sig_size eq 48 ? 'sha1' : 'sha256';
    }

    $self->{no_xml_declaration} = exists $params->{no_xml_declaration}
        && $params->{no_xml_declaration} ? 1 : 0;

    $self->{namespace} = {
        dsig => "http://www.w3.org/2000/09/xmldsig#",
        ec   => "http://www.w3.org/2001/10/xml-exc-c14n#",
    };

    return $self;
}

sub _slurp {
    my $file = shift;

    open my $fh, '<', $file or confess "Could not load $file: $!";

    local $/ = undef;
    my $text = <$fh>;
    return $text;
}

sub _load_key {
    my $self = shift;
    my $file = $self->{key};

    my $text = _slurp($file);

    return $self->_load_rsa_key($text)   if $text =~ m/BEGIN RSA PRIVATE KEY/;
    return $self->_load_dsa_key($text)   if $text =~ m/BEGIN DSA PRIVATE KEY/;
    return $self->_load_ecdsa_key($text) if $text =~ m/BEGIN EC PRIVATE KEY/;
    return $self->_load_rsa_key($text)   if $text =~ m/BEGIN PRIVATE KEY/;
    return $self->_load_x509_key($text)  if $text =~ m/BEGIN CERTIFICATE/;

    confess "Could not detect type of key $file.";
}

sub _load_rsa_key {
    my $self = shift;
    my ($key_text) = @_;

    my $rsaKey = Crypt::OpenSSL::RSA->new_private_key($key_text);
    confess "did not get a new Crypt::OpenSSL::RSA object" unless $rsaKey;

    $rsaKey->use_pkcs1_padding();
    $self->{key_obj}  = $rsaKey;
    $self->{key_type} = 'rsa';
    return 1;
}

sub _load_dsa_key {
    my $self     = shift;
    my $key_text = shift;

    my $dsa_key = Crypt::OpenSSL::DSA->read_priv_key_str($key_text);
    confess "did not get a new Crypt::OpenSSL::RSA object" unless $dsa_key;

    $self->{key_type} = 'dsa';
    $self->{key_obj}  = $dsa_key;
    return 1;
}

sub _load_ecdsa_key {
    my $self     = shift;
    my $key_text = shift;

    my $ecdsa_key = Crypt::PK::ECC->new(\$key_text);
    confess "did not get a new Crypt::PK::ECC object" unless $ecdsa_key;

    $self->{key_obj}  = $ecdsa_key;
    $self->{key_type} = 'ecdsa';
    return 1;
}

sub _load_x509_key {
    my $self     = shift;
    my $key_text = shift;

    my $x509Key = Crypt::OpenSSL::X509->new_private_key($key_text);
    confess "did not get a new Crypt::OpenSSL::X509 object" unless $x509Key;

    $x509Key->use_pkcs1_padding();
    $self->{key_obj}  = $x509Key;
    $self->{key_type} = 'x509';
    return 1;
}

sub _load_cert {
    my $self     = shift;
    my $filename = shift;
    my $text     = _slurp($filename);
    $self->_load_cert_text($text);
    return;
}

sub _load_cert_text {
    my $self = shift;
    my $text = shift;

    my $cert = Crypt::OpenSSL::X509->new_from_string($text);
    confess "Could not load certificate" unless $cert;
    $self->{cert_obj} = $cert;
    $self->{key_type} = 'x509cert';
    return;
}

sub _load_hmac_key {
    my $self = shift;
    $self->{key_type} = 'hmac';
    return 1;
}

=head3 B<sign($xml)>

When given a string of XML, it will return the same string with a signature
generated from the key provided when the XML::Sig object was initialized.

This method will sign all elements in your XML with an ID (case sensitive)
attribute. Each element with an ID attribute will be the basis for a seperate
signature. It will correspond to the URI attribute in the Reference element
that will be contained by the signature. If no ID attribute can be found on
an element, the signature will not be created.

The elements are signed in reverse order currently assuming (possibly
incorrectly) that the lower element in the tree may need to be signed
inclusive of its Signature because it is a child of the higher element.

Arguments:
    $xml:     string XML string

Returns: string  Signed XML

=cut

sub sign {
    my $self = shift;
    my $xml  = shift;

    croak "You cannot sign XML without a private key."
        unless $self->key || $self->{hmac_key};

    local $XML::LibXML::skipXMLDeclaration = $self->{no_xml_declaration};

    my $dom = XML::LibXML->load_xml(string => $xml);
    my $xpc = XML::LibXML::XPathContext->new($dom);
    $self->{parser} = $xpc;

    foreach (keys %{ $self->{namespace} }) {
        $xpc->registerNs($_, $self->{namespace}{$_});
    }

    if ($self->{ns}) {
        foreach (keys %{ $self->{ns} }) {
            $xpc->registerNs($_, $self->{ns}{$_});
        }
    }

    my @namespaces = $dom->findnodes('//*')->get_node(1)->getNamespaces();

    my $nodes = $self->_get_id_nodes();
    $nodes->reverse->foreach(
        sub {
            $self->sign_node($_, \@namespaces);
        }
    );
    return $dom->toString;
}

sub _get_id_nodes {
    my $self  = shift;
    my $xpc   = $self->{parser};
    my $nodes = $xpc->findnodes('//@ID/..');
    return $nodes unless $self->{attr_id};
    return scalar $xpc->findnodes("$self->{attr_id}/..", $nodes);
}

sub sign_node {
    my $self       = shift;
    my $node       = shift;
    my $namespaces = shift;

    my $d = XML::LibXML->createDocument;
    $self->{d} = $d;

    my $root = $d->createElementNS($self->{namespace}{dsig}, 'dsig:Signature');

    my $si = $d->createElement('dsig:SignedInfo');
    $si->setNamespace($self->{namespace}{dsig}, "dsig", 0);
    $root->addChild($si);

    ## TODO: add dsig and xenc namespaces to this node
    my $cm = $d->createElement('dsig:CanonicalizationMethod');
    ## TODO: Add algo in constructor
    $cm->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
    my $sm = $d->createElement('dsig:SignatureMethod');
    $sm->setAttribute('Algorithm', $self->get_signing_hash_algo);

    $si->addChild($cm);
    $si->addChild($sm);

    my $signid = $node->getAttribute('ID');

    my $ref = $d->createElement('dsig:Reference');
    $ref->setNamespace($self->{namespace}{dsig}, "dsig", 0);
    $si->addChild($ref);

    $ref->setAttribute(URI => "#$signid");
    my $t = $d->createElement('dsig:Transforms');
    $ref->addChild($t);

    ## TODO: Add algo in constructor
    my @algos = (
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#'
    );

    foreach (@algos) {
        my $n = $d->createElement('dsig:Transform');
        $n->setAttribute('Algorithm', "$_");
        $t->addChild($n);
    }

    my $dm = $d->createElement('dsig:DigestMethod');
    $dm->setAttribute("Algorithm", $self->_get_digest_algorith());

    my $tbs = $self->canonicalize_node($node, $namespaces, @algos);

    ### Canonicalize XML: $tbs

    my $digest = $self->calculate_digest($tbs);
    my $dv = $d->createElement('dsig:DigestValue');
    $dv->appendText($digest);

    $ref->addChild($dm);
    $ref->addChild($dv);

    my $sv = $d->createElement('dsig:SignatureValue');
    $root->addChild($sv);

    if(my $key_node = $self->get_key_info) {
        $root->addChild($key_node);
    }

    ### SignedInfo: $si->toString(2)

    my $sc = $self->canonicalize_node($si, $namespaces, @algos);

    ### SignedInfo (Canonicalize): $sc

    my $sig_method = sprintf('_calc_%s_signature', $self->{key_type});

    my $signature = encode_base64($self->$sig_method($sc), "");

    ### Signature with $self->{key_type} $sig_method: $signature

    $sv->appendText($signature);

    $node->addChild($root);
}

sub _calc_x509cert_signature {
    my $self = shift;
    return 'Undefined signature for now';
}

sub get_signing_hash_algo {
    my $self = shift;

    return
        "http://www.w3.org/2000/09/xmldsig#$self->{key_type}-$self->{sig_hash}"
        if $self->{sig_hash} eq 'sha1' && $self->{key_type} ne 'ecdsa';

    return
        "http://www.w3.org/2007/05/xmldsig-more#$self->{key_type}-$self->{sig_hash}"
        if $self->{key_type} eq 'ecdsa'
        && any { $_ eq $self->{sig_hash} } qw(ripemd160 whirlpool);

    return
        "http://www.w3.org/2001/04/xmldsig-more#$self->{key_type}-$self->{sig_hash}"
        if $self->{key_type} eq 'ecdsa';

    return
        "http://www.w3.org/2009/xmldsig11#$self->{key_type}-$self->{sig_hash}"
        if $self->{key_type} eq 'dsa' && $self->{sig_hash} eq 'sha256';

    return
        "http://www.w3.org/2001/04/xmldsig-more#$self->{key_type}-$self->{sig_hash}";
}


sub canonicalize_node {
    my $self = shift;
    my $node = shift;
    my $namespaces = shift;
    my @algos = @_;

    my $xml;
    my $last_alg;
    foreach my $alg (@algos) {
        my $x = $self->_transform_node($node, $namespaces, $alg);
        if ($x) {
            $xml = $x;
            $last_alg = $alg;
        }
    }

    confess "Unable to canonicalize node" unless $xml;

    local $XML::LibXML::skipXMLDeclaration = 1;
    my $tn = XML::LibXML->load_xml(string => $xml);
    return $self->_transform_node($tn, $namespaces, $last_alg);

}

sub _transform_node {
    my $self       = shift;
    my $node       = shift;
    my $namespaces = shift;
    my $alg        = shift;

    return if $alg eq TRANSFORM_ENV_SIG;

    return $node->toStringC14N()  if $alg eq TRANSFORM_C14N;
    return $node->toStringC14N(1) if $alg eq TRANSFORM_C14N_COMMENTS;

    # The following code is to circumvent a 11 yo quirck with
    # XML::LibXML::Element's. For more info see:
    # https://stackoverflow.com/questions/9296049/error-while-trying-to-canonize-xml-fragments-in-xmllibxml

    my $xml = $self->_transform_node_ec14n($node, $alg);
    return $xml if $xml;

    # Because we have to circumvent the issue we also need to add the namespace
    # to the node in order for us to parse it. Annoying but doable. We don't
    # add namespaces we already have and we don't add a namespace if it does
    # not exist a child
    foreach my $ns (@$namespaces) {
        my @ns     = $node->getNamespaces();
        my $urn    = $ns->getData;
        next if any { $_->getData eq $urn } @ns;

        my $prefix = $ns->getLocalName;

        # Test if we have the namespace, unfortunatly we cannot ask the xpc
        # which namespaces we have registered. But, if we get a prefix which
        # has a different urn configured we can change the prefix to something
        # custom and continue as planned. This bit is mostly tested by
        # t/026_do-not-move-namespace-to-parent.t
        my $have_urn = $self->{parser}->lookupNs($prefix);
        if ($have_urn eq $urn) {
            $self->{parser}->registerNs($prefix, $urn);
        }
        else {
            $prefix = "xml-sig_${prefix}";
            $self->{parser}->registerNs($prefix, $urn);
        }

        my $xpath = ".//$prefix:*";
        next unless $self->{parser}->exists($xpath, $node);
        $node->setNamespace($urn, $prefix, 0);
    }

    my $tmp = XML::LibXML->new->parse_string($node->toString);
    return $self->_transform_node_ec14n($tmp, $alg);


}

sub _transform_node_ec14n {
    my $self = shift;
    my $node = shift;
    my $alg  = shift;

    my @prefixlist = $self->_find_prefixlist($node);
    return $node->toStringEC14N(0, '', \@prefixlist)
        if $alg eq TRANSFORM_EXC_C14N;

    return $node->toStringEC14N(1, '', \@prefixlist)
        if $alg eq TRANSFORM_EXC_C14N;

    return;

}


sub calculate_digest {
    my $self = shift;
    my $xml  = shift;

    my $method     = $self->get_digest_method();
    my $bin_digest = $method->(encode_utf8($xml));
    my $digest     = encode_base64($bin_digest, '');
    return $digest;
}

sub get_digest_method {
    my $self = shift;
    if (my $ref = Digest::SHA->can($self->{digest_hash})) {
        return $ref;
    }
    if (my $ref = Crypt::Digest::RIPEMD160->can($self->{digest_hash})) {
        return $ref;
    }
    croak("Cannot resolv digest method for $self->{ digest_hash }");
}


=head3 B<verify($xml)>

Returns true or false based upon whether the signature is valid or not.

When using XML::Sig exclusively to verify a signature, no key needs to be
specified during initialization given that the public key should be
transmitted with the signature.

XML::Sig checks all signature in the provided xml and will fail should any
signature pointing to an existing ID in the XML fail to verify.

Should there be a Signature included that does not point to an existing node
in the XML it is ignored and other Signaures are checked.  If there are no
other Signatures it will return false.

Arguments:
    $xml:     string XML string

Returns: string  Signed XML

=cut

sub verify {
    my $self = shift;
    delete $self->{signer_cert};
    my $xml = shift;

    my $dom = XML::LibXML->load_xml(string => $xml);

    $self->{parser} = XML::LibXML::XPathContext->new($dom);
    $self->{parser}->registerNs('dsig', 'http://www.w3.org/2000/09/xmldsig#');
    $self->{parser}
        ->registerNs('ec', 'http://www.w3.org/2001/10/xml-exc-c14n#');
    $self->{parser}
        ->registerNs('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
    $self->{parser}
        ->registerNs('ecdsa', 'http://www.w3.org/2001/04/xmldsig-more#');

    my $signature_nodeset = $self->{parser}->findnodes('//dsig:Signature');

    my $key_to_verify;
    if ($self->{id_attr}) {
        if ($self->{ns}) {
            foreach (keys %{ $self->{ns} }) {
                $self->{parser}->registerNs($_, $self->{ns}{$_});
            }
        }
        $key_to_verify = $self->_get_ids_to_sign();
    }

    my $numsigs = $signature_nodeset->size();
    print("NodeSet Size: $numsigs\n") if $DEBUG;

    # Loop through each Signature in the document checking each
    my $i;
    while (my $signature_node = $signature_nodeset->shift()) {
        $i++;
        print("\nSignature $i\n") if $DEBUG;

        # Get SignedInfo Reference ID
        my $reference
            = $self->{parser}->findvalue('dsig:SignedInfo/dsig:Reference/@URI',
            $signature_node);
        $reference =~ s/#//g;

        print("   Reference URI: $reference\n") if $DEBUG;

        if ($key_to_verify && $key_to_verify ne $reference) {
            print(
                "Skipping reference URI: $reference, does not match required option\n"
            ) if $DEBUG;
            next;
        }

        # The reference ID must point to something in the document
        # if not disregard it and look for another signature
        # TODO check to ensure that if there is only a single reference
        # like this it won't accidentally validate
        if (!$self->{parser}->findvalue('//*[@ID=\'' . $reference . '\']')) {
            print(
                "   Signature reference $reference is not signing anything in this xml\n"
            ) if $DEBUG;
            if ($numsigs <= 1) {
                return 0;
            }
            else {
                next;
            }
        }

        # Get SignedInfo DigestMethod Algorithim
        my $digest_method
            = $self->{parser}->findvalue(
            'dsig:SignedInfo/dsig:Reference/dsig:DigestMethod/@Algorithm',
            $signature_node);
        $digest_method =~ s/^.*[#]//;
        print("   Digest Method: $digest_method\n") if $DEBUG;

        # Get the DigestValue used to verify Canonical XML
        # Note that the digest may have embedded newlines in the XML
        # Decode the base64 and encode it with no newlines
        my $refdigest = encode_base64(
            decode_base64(
                _trim(
                    $self->{parser}->findvalue(
                        'dsig:SignedInfo/dsig:Reference/dsig:DigestValue',
                        $signature_node
                    )
                )
            ),
            ""
        );
        print("   Digest Value: $refdigest\n") if $DEBUG;

        # Get the SignatureValue used to verify the SignedInfo
        my $signature
            = _trim(
            $self->{parser}->findvalue('dsig:SignatureValue', $signature_node)
            );
        print("   Signature: $signature\n") if $DEBUG;

        # Get SignatureMethod Algorithim
        my $signature_method
            = $self->{parser}
            ->findvalue('dsig:SignedInfo/dsig:SignatureMethod/@Algorithm',
            $signature_node);
        $signature_method =~ s/^.*[#]//;
        $signature_method =~ s/^rsa-//;
        $signature_method =~ s/^dsa-//;
        $signature_method =~ s/^ecdsa-//;
        $signature_method =~ s/^hmac-//;

        $self->{sig_hash} = $signature_method;
        print("   SignatureMethod: $signature_method\n") if $DEBUG;

        # Get the SignedInfo and obtain its Canonical form
        my ($signed_info)
            = $self->{parser}->findnodes('dsig:SignedInfo', $signature_node);
        my $signed_info_canon
            = $self->_canonicalize_xml($signed_info, $signature_node);

        print "$signed_info_canon\n" if $DEBUG;

        if (my $ref = Digest::SHA->can($signature_method)) {
            $self->{sig_method} = $ref;
        }
        elsif ($ref = Crypt::Digest::RIPEMD160->can($signature_method)) {
            $self->{sig_method} = $ref;
        }
        else {
            die("Can't handle $signature_method");
        }

        if (my $ref = Digest::SHA->can($digest_method)) {
            $self->{digest_method} = $ref;
        }
        elsif ($ref = Crypt::Digest::RIPEMD160->can($digest_method)) {
            $self->{digest_method} = $ref;
        }
        else {
            die("Can't handle $digest_method");
        }

        # If a cert was provided to XML::Sig->new() use it to
        # verify the SignedInfo signature
        if (defined $self->{cert_obj}) {

            # use the provided cert to verify
            unless (
                $self->_verify_x509_cert(
                    $self->{cert_obj}, $signed_info_canon, $signature
                )
                )
            {
                print STDERR "not verified by x509\n";
                return 0;
            }
        }
        elsif (!defined $self->{cert_obj} && defined $self->{hmac_key}) {

            # use the provided cert to verify
            unless ($self->_verify_hmac($signed_info_canon, $signature)) {
                print "not verified by hmac-" . $self->{sig_hash}, "\n"
                    if $DEBUG;
                return 0;
            }
        }

        # Extract the XML provided certificate and use it to
        # verify the SignedInfo signature
        else {
            # extract the certficate or key from the document
            my %verify_dispatch = (
                'X509Data'      => '_verify_x509',
                'RSAKeyValue'   => '_verify_rsa',
                'DSAKeyValue'   => '_verify_dsa',
                'ECDSAKeyValue' => '_verify_ecdsa',
            );
            my $keyinfo_nodeset;
            foreach my $key_info_sig_type (
                qw/X509Data RSAKeyValue DSAKeyValue ECDSAKeyValue/)
            {
                if ($key_info_sig_type eq 'X509Data') {
                    $keyinfo_nodeset
                        = $self->{parser}
                        ->find("dsig:KeyInfo/dsig:$key_info_sig_type",
                        $signature_node);

                    #print ("   keyinfo_nodeset X509Data: $keyinfo_nodeset\n") if $DEBUG;
                }
                else {
                    $keyinfo_nodeset
                        = $self->{parser}->find(
                        "dsig:KeyInfo/dsig:KeyValue/dsig:$key_info_sig_type",
                        $signature_node);

                    #print ("   keyinfo_nodeset [DR]SAKeyValue: $keyinfo_nodeset\n") if $DEBUG;
                }
                if ($keyinfo_nodeset->size) {
                    my $verify_method = $verify_dispatch{$key_info_sig_type};
                    print("   Verify Method: $verify_method\n") if $DEBUG;
                    if (
                        !$self->$verify_method(
                            $keyinfo_nodeset->get_node(0),
                            $signed_info_canon,
                            $signature
                        )
                        )
                    {
                        print("keyinfo_nodeset->get_node: "
                                . $keyinfo_nodeset->get_node(0) . "\n")
                            if $DEBUG;
                        print STDERR "Failed to verify using $verify_method\n";
                        return 0;
                    }
                    else {
                        print("Success Verifying\n") if $DEBUG;
                    }
                    last;
                }
            }
            die "Unrecognized key type or no KeyInfo in document"
                unless ($keyinfo_nodeset && $keyinfo_nodeset->size > 0);
        }

        # Signature of SignedInfo was verified above now obtain the
        # Canonical form of the XML and verify the DigestValue of the XML

        # Remove the Signature from the signed XML
        my $signed_xml = $self->_get_signed_xml($signature_node);
        $signed_xml->removeChild($signature_node);

        # Obtain the Canonical form of the XML
        my $canonical = $self->_transform($signed_xml, $signature_node);

        # Add the $signature_node back to the $signed_xml to allow other
        # signatures to be validated if they exist
        $signed_xml->addChild($signature_node);

        print("    Canonical XML:  " . $canonical . "\n") if $DEBUG;

        # Obtain the DigestValue of the Canonical XML
        my $digest = $self->{digest_method}->(Encode::encode_utf8($canonical));

        print("    Reference Digest:  " . _trim($refdigest) . "\n") if $DEBUG;

        print("    Calculated Digest: "
                . _trim(encode_base64($digest, '')) . "\n")
            if $DEBUG;

        # Return 0 - fail verification on the first XML signature that fails
        return 0 unless ($refdigest eq _trim(encode_base64($digest, '')));

        print("Signature $i Valid\n") if $DEBUG;
    }

    return 1;
}

=head3 B<signer_cert()>

Following a successful verify with an X509 certificate, returns the
signer's certificate as embedded in the XML document for verification
against a CA certificate. The certificate is returned as a
Crypt::OpenSSL::X509 object.

Arguments: none

Returns: Crypt::OpenSSL::X509: Certificate used to sign the XML

=cut

sub signer_cert {
    my $self = shift;
    return $self->{signer_cert};
}

##
## _get_ids_to_sign()
##
## Arguments:
##
## Returns: array Value of ID attributes from XML
##
## Finds all the values of the ID attributes in the XML
## and return them in reverse order found.  Reverse order
## assumes that the Signatures should be performed on lower
## Nodes first.
##
sub _get_ids_to_sign {
    my $self = shift;

    if ($self->{id_attr}) {
        my $nodes = $self->{parser}->findnodes($self->{id_attr});
        if ($nodes->size == 0) {
            die "Unable to find an attribute node with $self->{id_attr}";
        }
        my $node = $nodes->get_node(1);
        return $node->getAttribute('ID');

    }

    my $nodes = $self->{parser}->findnodes('//@ID');
    return $nodes->reverse->map(
        sub {
            my $val = $_->getValue;
            defined($val) && length($val) && $val;
        }
    );
}

##
## _get_xml_to_sign()
##
## Arguments:
##    $id:     string ID of the Node for the XML to retrieve
##
## Returns: XML NodeSet to sign
##
## Find the XML node with the ID = $id and return the
## XML NodeSet
##
sub _get_xml_to_sign {
    my $self = shift;
    my $id   = shift;
    die
        "You cannot sign an XML document without identifying the element to sign with an ID attribute"
        unless $id;

    my $xpath = "//*[\@ID='$id']";
    my ($node) = $self->_get_node($xpath);
    return $node;
}

##
## _get_signed_xml($context)
##
## Arguments:
##    $context:     string XML NodeSet used as context
##
## Returns: XML NodeSet for with ID equal to the URI
##
## Find the XML node with the ID = $URI and return the
## XML NodeSet
##
sub _get_signed_xml {
    my $self = shift;
    my ($context) = @_;

    my $id = $self->{parser}
        ->findvalue('./dsig:SignedInfo/dsig:Reference/@URI', $context);
    $id =~ s/^#//;
    print("    Signed XML id: $id\n") if $DEBUG;

    $self->{'sign_id'} = $id;
    my $xpath = "//*[\@ID='$id']";
    return $self->_get_node($xpath, $context);
}

##
## _transform($xml, $context)
##
## Arguments:
##    $xml:     string XML NodeSet
##    $context: string XML Context
##
## Returns: string  Transformed XML
##
## Canonicalizes/Transforms xml based on the Transforms
## from the SignedInfo.
##
sub _transform {
    my $self = shift;
    my ($xml, $context) = @_;

    $context->setNamespace($self->{namespace}{dsig}, 'dsig');
    my $transforms
        = $self->{parser}
        ->find('dsig:SignedInfo/dsig:Reference/dsig:Transforms/dsig:Transform',
        $context);

    print "_transform\n" if $DEBUG;
    foreach my $node ($transforms->get_nodelist) {
        my $alg = $node->getAttribute('Algorithm');

        print "    Algorithm: $alg\n" if $DEBUG;
        if ($alg eq TRANSFORM_ENV_SIG) {

            # TODO the xml being passed here currently has the
            # Signature removed.  May be better to do it all here
            next;
        }
        elsif ($alg eq TRANSFORM_C14N) {
            print "        toStringC14N" if $DEBUG;
            $xml = $xml->toStringC14N();
        }
        elsif ($alg eq TRANSFORM_C14N_COMMENTS) {
            print "        toStringC14N(1)" if $DEBUG;
            $xml = $xml->toStringC14N(1);
        }
        elsif ($alg eq TRANSFORM_EXC_C14N) {
            my @prefixlist = $self->_find_prefixlist($node);
            print "        toStringEC14N(0, '', @prefixlist)\n" if $DEBUG;
            $xml = $xml->toStringEC14N(0, '', \@prefixlist);
        }
        elsif ($alg eq TRANSFORM_EXC_C14N_COMMENTS) {
            my @prefixlist = $self->_find_prefixlist($node);
            print "        toStringEC14N(1, '', @prefixlist)\n" if $DEBUG;
            $xml = $xml->toStringEC14N(1, '', \@prefixlist);
        }
        else {
            die "Unsupported transform: $alg";
        }
    }
    return $xml;
}

##
## _find_prefixlist($node)
##
## Arguments:
##    $node:    string XML NodeSet
##
## Returns: ARRAY of prefix lists
##
## Generate an array of prefix lists defined in InclusiveNamespaces
##
sub _find_prefixlist {
    my $self = shift;
    my $node = shift;

    return unless $node->can('getChildrenByLocalName');

    my @children = $node->getChildrenByLocalName('InclusiveNamespaces');

    my @list;
    foreach my $child (@children) {
        my $p = $child->getAttribute('PrefixList');
        push(@list, split(/\s+/, $p)) if $p;
    }
    return @list;
}

##
## _verify_rsa($context,$canonical,$sig)
##
## Arguments:
##    $context:     string XML Context to use
##    $canonical:   string Canonical XML to verify
##    $sig:         string Base64 encode of RSA Signature
##
## Returns: integer (1 True, 0 False) if signature is valid
##
## Verify the RSA signature of Canonical XML
##
sub _verify_rsa {
    my $self = shift;
    my ($context, $canonical, $sig) = @_;

    # Generate Public Key from XML
    my $mod     = _trim($self->{parser}->findvalue('dsig:Modulus', $context));
    my $modBin  = decode_base64($mod);
    my $exp     = _trim($self->{parser}->findvalue('dsig:Exponent', $context));
    my $expBin  = decode_base64($exp);
    my $n       = Crypt::OpenSSL::Bignum->new_from_bin($modBin);
    my $e       = Crypt::OpenSSL::Bignum->new_from_bin($expBin);
    my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters($n, $e);

    # Decode signature and verify
    my $sig_hash = 'use_' . $self->{sig_hash} . '_hash';
    $rsa_pub->$sig_hash;
    my $bin_signature = decode_base64($sig);
    return 1 if ($rsa_pub->verify($canonical, $bin_signature));
    return 0;
}

##
## _clean_x509($cert)
##
## Arguments:
##    $cert:     string Certificate in base64 from XML
##
## Returns: string  Certificate in Valid PEM format
##
## Reformats Certifcate string into PEM format 64 characters
## with proper header and footer
##
sub _clean_x509 {
    my $self = shift;
    my ($cert) = @_;

    $cert = $cert->value() if (ref $cert);
    chomp($cert);

    # rewrap the base64 data from the certificate; it may not be
    # wrapped at 64 characters as PEM requires
    $cert =~ s/\n//g;

    my @lines;
    while (length $cert > 64) {
        push @lines, substr $cert, 0, 64, '';
    }
    push @lines, $cert;

    $cert = join "\n", @lines;

    $cert
        = "-----BEGIN CERTIFICATE-----\n"
        . $cert
        . "\n-----END CERTIFICATE-----\n";
    return $cert;
}

##
## _verify_x509($context,$canonical,$sig)
##
## Arguments:
##    $context:     string XML Context to use
##    $canonical:   string Canonical XML to verify
##    $sig:         string Base64 encode of RSA Signature
##
## Returns: integer (1 True, 0 False) if signature is valid
##
## Verify the RSA signature of Canonical XML using an X509
##
sub _verify_x509 {
    my $self = shift;
    my ($context, $canonical, $sig) = @_;

    # Generate Public Key from XML
    my $certificate
        = _trim($self->{parser}->findvalue('dsig:X509Certificate', $context));

    # This is added because the X509 parser requires it for self-identification
    $certificate = $self->_clean_x509($certificate);

    my $cert = Crypt::OpenSSL::X509->new_from_string($certificate);

    return $self->_verify_x509_cert($cert, $canonical, $sig);
}

##
## _verify_x509_cert($cert,$canonical,$sig)
##
## Arguments:
##    $cert:        string X509 Certificate
##    $canonical:   string Canonical XML to verify
##    $sig:         string Base64 encode of [EC|R]SA Signature
##
## Returns: integer (1 True, 0 False) if signature is valid
##
## Verify the X509 signature of Canonical XML
##
sub _verify_x509_cert {
    my $self = shift;
    my ($cert, $canonical, $sig) = @_;

    # Decode signature and verify
    my $bin_signature = decode_base64($sig);

    if ($cert->key_alg_name eq 'id-ecPublicKey') {
        my $ecdsa_pub = Crypt::PK::ECC->new(\$cert->pubkey);

        my $ecdsa_hash = $self->{rsa_hash};

        # Signature is stored as the concatenation of r and s.
        # verify_message_rfc7518 expects that format
        if (
            $ecdsa_pub->verify_message_rfc7518(
                $bin_signature, $canonical, uc($self->{sig_hash})
            )
            )
        {
            $self->{signer_cert} = $cert;
            return 1;
        }
    }
    elsif ($cert->key_alg_name eq 'dsaEncryption') {

        my $dsa_pub  = Crypt::OpenSSL::DSA->read_pub_key_str($cert->pubkey);
        my $sig_size = ($dsa_pub->get_sig_size - 8) / 2;

        #my ($r, $s) = unpack('a20a20', $bin_signature);
        my $unpk = "a" . $sig_size . "a" . $sig_size;
        my ($r, $s) = unpack($unpk, $bin_signature);

        # Create a new Signature Object from r and s
        my $sigobj = Crypt::OpenSSL::DSA::Signature->new();
        $sigobj->set_r($r);
        $sigobj->set_s($s);

        if ($dsa_pub->do_verify($self->{sig_method}->($canonical), $sigobj)) {
            $self->{signer_cert} = $cert;
            return 1;
        }
    }
    else {
        my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($cert->pubkey);

        my $sig_hash = 'use_' . $self->{sig_hash} . '_hash';
        $rsa_pub->$sig_hash();

        # If successful verify, store the signer's cert for validation
        if ($rsa_pub->verify($canonical, $bin_signature)) {
            $self->{signer_cert} = $cert;
            return 1;
        }
    }

    return 0;
}

##
## _zero_fill_buffer($bits)
##
## Arguments:
##    $bits:     number of bits to set to zero
##
## Returns: Zero filled bit buffer of size $bits
##
## Create a buffer with all bits set to 0
##
sub _zero_fill_buffer {
    my $bits = shift;

    # set all bit to zero
    my $v = '';
    for (my $i = 0; $i < $bits; $i++) {
        vec($v, $i, 1) = 0;
    }
    return $v;
}

##
## _concat_dsa_sig_r_s(\$buffer,$r,$s)
##
## Arguments:
##    $buffer:      Zero Filled bit buffer
##    $r:           octet stream
##    $s:           octet stream
##
## Combine r and s components of DSA signature
##
sub _concat_dsa_sig_r_s {

    my ($buffer, $r, $s, $sig_size) = @_;
    my $bits_r = (length($r) * 8) - 1;
    my $bits_s = (length($s) * 8) - 1;

    my $halfsize = $sig_size / 2;

    # Place $s right justified in $v starting at bit 319
    for (my $i = $bits_s; $i >= 0; $i--) {
        vec($$buffer, $halfsize + $i + (($halfsize - 1) - $bits_s), 1)
            = vec($s, $i, 1);
    }

    # Place $r right justified in $v starting at bit 159
    for (my $i = $bits_r; $i >= 0; $i--) {
        vec($$buffer, $i + (($halfsize - 1) - $bits_r), 1) = vec($r, $i, 1);
    }

}

##
## _verify_dsa($context,$canonical,$sig)
##
## Arguments:
##    $context:     string XML Context to use
##    $canonical:   string Canonical XML to verify
##    $sig:         string Base64 encode 40 byte string of r and s
##
## Returns: integer (1 True, 0 False) if signature is valid
##
## Verify the DSA signature of Canonical XML
##
sub _verify_dsa {
    my $self = shift;
    my ($context, $canonical, $sig) = @_;

    # Generate Public Key from XML
    my $p
        = decode_base64(_trim($self->{parser}->findvalue('dsig:P', $context)));
    my $q
        = decode_base64(_trim($self->{parser}->findvalue('dsig:Q', $context)));
    my $g
        = decode_base64(_trim($self->{parser}->findvalue('dsig:G', $context)));
    my $y
        = decode_base64(_trim($self->{parser}->findvalue('dsig:Y', $context)));
    my $dsa_pub = Crypt::OpenSSL::DSA->new();
    $dsa_pub->set_p($p);
    $dsa_pub->set_q($q);
    $dsa_pub->set_g($g);
    $dsa_pub->set_pub_key($y);

    # Decode signature and verify
    my $bin_signature = decode_base64($sig);

    # https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/#sec-SignatureAlg
    # The output of the DSA algorithm consists of a pair of integers
    # The signature value consists of the base64 encoding of the
    # concatenation of r and s in that order ($r . $s)
    # Binary Signature is stored as a concatenation of r and s
    my $sig_size = ($dsa_pub->get_sig_size - 8) / 2;
    my $unpk     = "a" . $sig_size . "a" . $sig_size;
    my ($r, $s) = unpack($unpk, $bin_signature);

    # Create a new Signature Object from r and s
    my $sigobj = Crypt::OpenSSL::DSA::Signature->new();
    $sigobj->set_r($r);
    $sigobj->set_s($s);

    # DSA signatures are limited to a message body of 20 characters, so a sha1 digest is taken
    return 1
        if ($dsa_pub->do_verify($self->{sig_method}->($canonical), $sigobj));
    return 0;
}

##
## _verify_ecdsa($context,$canonical,$sig)
##
## Arguments:
##    $context:     string XML Context to use
##    $canonical:   string Canonical XML to verify
##    $sig:         string Base64 encoded
##
## Returns: integer (1 True, 0 False) if signature is valid
##
## Verify the ECDSA signature of Canonical XML
##
sub _verify_ecdsa {
    my $self = shift;
    my ($context, $canonical, $sig) = @_;

    eval { require Crypt::PK::ECC; CryptX->VERSION('0.036'); 1 }
        or confess "Crypt::PK::ECC 0.036+ needs to be installed so
             that we can handle ECDSA signatures";

    # Generate Public Key from XML
    my $oid = _trim(
        $self->{parser}->findvalue('.//dsig:NamedCurve/@URN', $context));

    use URI ();
    my $u1 = URI->new($oid);
    $oid = $u1->nss;

    my %curve_name = (
        '1.2.840.10045.3.1.1'   => 'secp192r1',
        '1.3.132.0.33'          => 'secp224r1',
        '1.2.840.10045.3.1.7'   => 'secp256r1',
        '1.3.132.0.34'          => 'secp384r1',
        '1.3.132.0.35'          => 'secp521r1',
        '1.3.36.3.3.2.8.1.1.1'  => 'brainpoolP160r1',
        '1.3.36.3.3.2.8.1.1.3'  => 'brainpoolP192r1',
        '1.3.36.3.3.2.8.1.1.5'  => 'brainpoolP224r1',
        '1.3.36.3.3.2.8.1.1.7'  => 'brainpoolP256r1',
        '1.3.36.3.3.2.8.1.1.9'  => 'brainpoolP320r1',
        '1.3.36.3.3.2.8.1.1.11' => 'brainpoolP384r1',
        '1.3.36.3.3.2.8.1.1.13' => 'brainpoolP512r1',
    );

    my $x = $self->{parser}
        ->findvalue('.//dsig:PublicKey/dsig:X/@Value', $context);
    my $y = $self->{parser}
        ->findvalue('.//dsig:PublicKey/dsig:Y/@Value', $context);

    my $ecdsa_pub = Crypt::PK::ECC->new();

    $ecdsa_pub->import_key(
        {
            kty        => "EC",
            curve_name => $curve_name{$oid},
            pub_x      => $x,
            pub_y      => $y,
        }
    );

    my $bin_signature = decode_base64($sig);

    # verify_message_rfc7518 is used to verify signature stored as a
    # concatenation of integers r and s
    return 1
        if (
        $ecdsa_pub->verify_message_rfc7518(
            $bin_signature, $canonical, uc($self->{sig_hash})
        )
        );
    return 0;
}

##
## _verify_hmac($canonical, $sig)
##
## Arguments:
##    $canonical:   string Canonical XML to verify
##    $sig:         string Base64 encode of HMAC Signature
##
## Returns: integer (1 True, 0 False) if signature is valid
##
## Verify the HMAC signature of Canonical XML
##
sub _verify_hmac {
    my $self = shift;
    my ($canonical, $sig) = @_;

    # Decode signature and verify
    my $bin_signature = decode_base64($sig);
    use Crypt::Mac::HMAC qw( hmac );
    if (defined $self->{hmac_key}) {
        print("    Verifying SignedInfo using hmac-", $self->{sig_hash}, "\n")
            if $DEBUG;
        if (my $ref = Digest::SHA->can('hmac_' . $self->{sig_hash})) {
            if ($bin_signature eq $self->_calc_hmac_signature($canonical)) {
                return 1;
            }
            else {
                return 0;
            }
        }
        elsif ($ref = Crypt::Digest::RIPEMD160->can($self->{sig_hash})) {
            if ($bin_signature eq $self->_calc_hmac_signature($canonical)) {
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            die("Can't handle $self->{ sig_hash }");
        }

    }
    else {
        return 0;
    }
}

##
## _get_node($xpath, context)
##
## Arguments:
##    $xpath:       string XML XPath to use
##    $context:     string XML context
##
## Returns: string  XML NodeSet
##
## Return a NodeSet based on the xpath string
##
sub _get_node {
    my $self = shift;
    my ($xpath, $context) = @_;
    my $nodeset;
    if ($context) {
        $nodeset = $self->{parser}->find($xpath, $context);
    }
    else {
        $nodeset = $self->{parser}->find($xpath);
    }
    foreach my $node ($nodeset->get_nodelist) {
        return $node;
    }
}

##
## _trim($string)
##
## Arguments:
##    $string:      string String to remove whitespace
##
## Returns: string  Trimmed String
##
## Trim the whitespace from the begining and end of the string
##
sub _trim {
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}


=head2 get_key_info

Returns the XML::LibXML::Element for the KeyInfo section of the Signature

=cut

sub get_key_info {
    my $self = shift;

    return if $self->{x509};
    my $method = "get_$self->{key_type}_key";
    return $self->$method;
}

=head2 get_ecda_key

Returns the XML::LibXML::Element for the KeyInfo section of the Signature when
we have an edsa key

=cut

sub get_ecdsa_key {
    my $self = shift;

    state $ecdsa_key;
    return $ecdsa_key if $ecdsa_key;

    my $key_hash = $self->{key_obj}->key2hash;

    my $oid = $key_hash->{curve_oid};
    my $x   = $key_hash->{pub_x};
    my $y   = $key_hash->{pub_y};

    my ($d, $root) = $self->_make_KeyInfo_node();
    my $kv   = $d->createElement('dsig:KeyValue');
    $root->addChild($kv);
    my $ekv   = $d->createElement('dsig:ECDSAKeyValue');
    $kv->addChild($ekv);
    my $dp = $d->createElement('dsig:DomainParameters');
    $ekv->addChild($dp);

    my $nc = $d->createElement('dsig:NamedCurve');
    $nc->setAttribute('URN' => "urn:oid:$oid");
    $dp->addChild($nc);

    my $pk = $d->createElement('dsig:PublicKey');
    $ekv->addChild($pk);

    my $xe = $d->createElement('dsig:X');
    $xe->setAttribute('Value' => $x);
    my $ye = $d->createElement('dsig:Y');
    $ye->setAttribute('Value' => $y);

    $pk->addChild($xe);
    $pk->addChild($ye);

    $ecdsa_key = $root;
    return $ecdsa_key;

}


=head2 get_dsa_key

Returns the XML::LibXML::Element for the KeyInfo section of the Signature when
we have an DSA key

=cut

sub get_dsa_key {
    my $self = shift;

    state $dsa_key;
    return $dsa_key if $dsa_key;

    my ($d, $root) = $self->_make_KeyInfo_node();
    my $kv   = $d->createElement('dsig:KeyValue');
    $root->addChild($kv);

    my $ekv   = $d->createElement('dsig:DSAKeyValue');
    $kv->addChild($ekv);
    my $dp = $d->createElement('dsig:P');
    $ekv->addChild($dp);
    my $dq = $d->createElement('dsig:Q');
    $ekv->addChild($dq);
    my $dg = $d->createElement('dsig:G');
    $ekv->addChild($dg);
    my $dy = $d->createElement('dsig:Y');
    $ekv->addChild($dy);

    $dp->appendText(encode_base64($self->{key_obj}->get_p(),''));
    $dq->appendText(encode_base64($self->{key_obj}->get_q(),''));
    $dg->appendText(encode_base64($self->{key_obj}->get_g(),''));
    $dy->appendText(encode_base64($self->{key_obj}->get_pub_key(),''));

    $dsa_key = $root;
    return $dsa_key;
}

=head2 get_rsa_key

Returns the XML::LibXML::Element for the KeyInfo section of the Signature when
we have a RSA key

=cut

sub get_rsa_key {
    my $self = shift;

    confess "Unable to generate KeyInfo segment when x509 is involved" if $self->{x509};

    state $rsa_key;
    return $rsa_key if $rsa_key;

    my $rsaKey = $self->{key_obj};

    my @params = $rsaKey->get_key_parameters();

    my ($d, $root) = $self->_make_KeyInfo_node();

    my $rkv = $d->createElement('dsig:RSAKeyValue');

    $self->_add_KeyValue_node($d, $root, $rkv);

    my $mod = encode_base64($params[0]->to_bin(), "\n");
    my $m = $d->createElement('dsig:Modulus');
    $m->appendText($mod);
    $rkv->addChild($m);

    my $e = $d->createElement('dsig:Exponent');
    my $exp = encode_base64($params[1]->to_bin(), '');
    $e->appendText($exp);
    $rkv->addChild($e);

    $rsa_key = $root;
    return $rsa_key;
}

=head2 get_hmac_key

Returns the XML::LibXML::Element for the KeyInfo section of the Signature when
we have a HMAC key

=cut

sub _make_KeyInfo_node {
    my $self = shift;

    my $d = XML::LibXML->createDocument;
    my $root = $d->createElementNS($self->{namespace}{dsig}, 'dsig:KeyInfo');
    return ($d, $root);
}

sub _add_KeyValue_node {
    my $self = shift;
    my $d    = shift;
    my $root = shift;
    my $node = shift;

    my $kv   = $d->createElement('dsig:KeyValue');
    $root->addChild($kv);
    $kv->addChild($node);

}

sub get_hmac_key {
    my $self = shift;

    state $hmac_key;
    return $hmac_key if $hmac_key;

    die "Unable to create hmac key info" unless $self->{key_name};

    my ($d, $root) = $self->_make_KeyInfo_node();
    my $kv = $d->createElement('dsig:KeyName');
    $root->addChild($kv);
    $kv->appendText($self->{key_name});

    $hmac_key = $root;
    return $hmac_key;
}


sub get_x509cert_key {
    my $self = shift;

    state $x509;
    return $x509 if $x509;

    my $cert_text = $self->_get_cert_text;


    my ($d, $root) = $self->_make_KeyInfo_node();
    my $x509_data   = $d->createElement('dsig:X509Data');
    $root->addChild($x509_data);
    my $x509_cert = $d->createElement('dsig:X509Certificate');
    $x509_data->addChild($x509_cert);
    $x509_cert->appendText(_trim($cert_text));

    $x509 = $root;
    return $x509;
}

sub _get_cert_text {
    my $self = shift;
    my $text = $self->{cert_obj}->as_string;
    $text =~ s/-----[^-]*-----//gm;
    return _trim($text);
}

sub _get_digest_algorith {
    my $self = shift;
    my $digest_hash = $self->{digest_hash};
    return "http://www.w3.org/2000/09/xmldsig#$digest_hash"
        if $digest_hash eq 'sha1';
    return "http://www.w3.org/2001/04/xmldsig-more#$digest_hash"
        if any { $_ eq $digest_hash } qw(sha224 sha384);
    return "http://www.w3.org/2001/04/xmlenc#$digest_hash";
}

##
## _canonicalize_xml($xml, $context)
##
## Arguments:
##    $xml:     string XML NodeSet
##    $context: string XML Context
##
## Returns: string  Canonical XML
##
## Canonicalizes xml based on the CanonicalizationMethod
## from the SignedInfo.
##
sub _canonicalize_xml {
    my $self = shift;
    my ($xml, $context) = @_;

    print("_canonicalize_xml:\n") if $DEBUG;
    my $canon_method = $self->{parser}
        ->findnodes('dsig:SignedInfo/dsig:CanonicalizationMethod', $context);

    foreach my $node ($canon_method->get_nodelist) {
        my $alg = $node->getAttribute('Algorithm');

        print("    Canon Method: $alg\n") if $DEBUG;
        if ($alg eq TRANSFORM_C14N) {
            print("        toStringC14N\n") if $DEBUG;
            $xml = $xml->toStringC14N();
        }
        elsif ($alg eq TRANSFORM_C14N_COMMENTS) {
            print("        toStringC14N_Comments\n") if $DEBUG;
            $xml = $xml->toStringC14N(1);
        }
        elsif ($alg eq TRANSFORM_C14N_V1_1) {
            print("        toStringC14N_v1_1\n") if $DEBUG;
            $xml = $xml->toStringC14N_v1_1();
        }
        elsif ($alg eq TRANSFORM_C14N_V1_1_COMMENTS) {
            print("        toStringC14N_v1_1_Comments\n") if $DEBUG;
            $xml = $xml->toStringC14N_v1_1(1);
        }
        elsif ($alg eq TRANSFORM_EXC_C14N) {
            print("        toStringEC14N\n") if $DEBUG;
            $xml = $xml->toStringEC14N();
        }
        elsif ($alg eq TRANSFORM_EXC_C14N_COMMENTS) {
            print("        toStringEC14N_Comments\n") if $DEBUG;
            $xml = $xml->toStringEC14N(1);
        }
        else {
            die "Unsupported transform: $alg";
        }
    }
    return $xml;
}

##
## _calc_dsa_signature($signed_info_canon)
##
## Arguments:
##    $canonical:     string Canonical XML
##
## Returns: string  Signature
##
## Calculates signature based on the method and hash
##
sub _calc_dsa_signature {
    my $self              = shift;
    my $signed_info_canon = shift;

    print("    Signing SignedInfo using DSA key type\n") if $DEBUG;
    if (my $ref = Digest::SHA->can($self->{sig_hash})) {
        $self->{sig_method} = $ref;
    }
    elsif ($ref = Crypt::Digest::RIPEMD160->can($self->{sig_hash})) {
        $self->{sig_method} = $ref;
    }
    else {
        die("Can't handle $self->{ sig_hash }");
    }

    # DSA 1024-bit only permits the signing of 20 bytes or less, hence the sha1
    # DSA 2048-bit only permits the signing sha256
    my $bin_signature
        = $self->{key_obj}->do_sign($self->{sig_method}($signed_info_canon));

    # https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/#sec-SignatureAlg
    # The output of the DSA algorithm consists of a pair of integers
    # The signature value consists of the base64 encoding of the
    # concatenation of r and s in that order ($r . $s)
    my $r = $bin_signature->get_r;
    my $s = $bin_signature->get_s;

    my $sig_size = ($self->{key_obj}->get_sig_size - 8) * 8;
    my $rs       = _zero_fill_buffer($sig_size);
    _concat_dsa_sig_r_s(\$rs, $r, $s, $sig_size);

    return $rs;

}

##
## _calc_ecdsa_signature($signed_info_canon)
##
## Arguments:
##    $canonical:     string Canonical XML
##
## Returns: string  Signature
##
## Calculates signature based on the method and hash
##
sub _calc_ecdsa_signature {
    my $self              = shift;
    my $signed_info_canon = shift;

    ### _calc_ecdsa_signature with $self->{sig_hash}

    my $bin_signature = $self->{key_obj}
        ->sign_message_rfc7518($signed_info_canon, uc($self->{sig_hash}));

    # The output of the ECDSA algorithm consists of a pair of integers
    # The signature value consists of the base64 encoding of the
    # concatenation of r and s in that order ($r . $s).  In this
    # case sign_message_rfc7518 produces that
    return $bin_signature;
}

##
## _calc_rsa_signature($signed_info_canon)
##
## Arguments:
##    $canonical:     string Canonical XML
##
## Returns: string  Signature
##
## Calculates signature based on the method and hash
##
sub _calc_rsa_signature {
    my $self              = shift;
    my $signed_info_canon = shift;

    my $sig_hash = 'use_' . $self->{sig_hash} . '_hash';
    $self->{key_obj}->$sig_hash;
    return scalar $self->{key_obj}->sign($signed_info_canon);
}

##
## _calc_hmac_signature($signed_info_canon)
##
## Arguments:
##    $signed_info_canon:     string Canonical XML
##
## Returns: string  Signature
##
## Calculates signature based on the method and hash
##
sub _calc_hmac_signature {
    my $self              = shift;
    my $signed_info_canon = shift;

    use Crypt::Mac::HMAC qw( hmac );
    my $bin_signature;
    print("    Signing SignedInfo using hmac-", $self->{sig_hash}, "\n")
        if $DEBUG;
    if (my $ref = Digest::SHA->can('hmac_' . $self->{sig_hash})) {
        $self->{sig_method} = $ref;
        $bin_signature = $self->{sig_method}
            ($signed_info_canon, decode_base64($self->{hmac_key}));
    }
    elsif ($ref = Crypt::Digest::RIPEMD160->can($self->{sig_hash})) {
        $self->{sig_method} = $ref;
        $bin_signature = hmac('RIPEMD160', decode_base64($self->{hmac_key}),
            $signed_info_canon);
    }
    else {
        die("Can't handle $self->{ sig_hash }");
    }

    return $bin_signature;
}
1;
__END__

}

=head1 ABOUT DIGITAL SIGNATURES

Just as one might want to send an email message that is cryptographically signed
in order to give the recipient the means to independently verify who sent the email,
one might also want to sign an XML document. This is especially true in the
scenario where an XML document is received in an otherwise unauthenticated
context, e.g. SAML.

However XML provides a challenge that email does not. In XML, two documents can be
byte-wise inequivalent, and semanticaly equivalent at the same time. For example:

    <?xml version="1.0"?>
    <foo>
      <bar />
    </foo>

    And:

    <?xml version="1.0"?>
    <foo>
      <bar></bar>
    </foo>

Each of these document express the same thing, or in other words they "mean"
the same thing. However if you were to strictly sign the raw text of these
documents, they would each produce different signatures.

XML Signatures on the other hand will produce the same signature for each of
the documents above. Therefore an XML document can be written and rewritten by
different parties and still be able to have someone at the end of the line
verify a signature the document may contain.

There is a specially subscribed methodology for how this process should be
executed and involves transforming the XML into its canonical form so a
signature can be reliably inserted or extracted for verification. This
module implements that process.

=head2 EXAMPLE SIGNATURE

Below is a sample XML signature to give you some sense of what they look like.
First let's look at the original XML document, prior to being signed:

  <?xml version="1.0"?>
  <foo ID="abc">
    <bar>123</bar>
  </foo>

Now, let's insert a signature:

  <?xml version="1.0"?>
  <foo ID="abc">
    <bar>123</bar>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
        <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" />
        <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
        <Reference URI="#abc">
          <Transforms>
            <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
          </Transforms>
          <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
          <DigestValue>9kpmrvv3peVJpNSTRycrV+jeHVY=</DigestValue>
        </Reference>
      </SignedInfo>
      <SignatureValue>
        HXUBnMgPJf//j4ihaWnaylNwAR5AzDFY83HljFIlLmTqX1w1C72ZTuRObvYve8TNEbVsQlTQkj4R
        hiY0pgIMQUb75GLYFtc+f0YmBZf5rCWY3NWzo432D3ogAvpEzYXEQPmicWe2QozQhybaz9/wrYki
        XiXY+57fqCkf7aT8Bb6G+fn7Aj8gnZFLkmKxwCdyGsIZOIZdQ8MWpeQrifxBR0d8W1Zm6ix21WNv
        ONt575h7VxLKw8BDhNPS0p8CS3hOnSk29stpiDMCHFPxAwrbKVL1kGDLaLZn1q8nNRmH8oFxG15l
        UmS3JXDZAss8gZhU7g9T4XllCqjrAvzPLOFdeQ==
      </SignatureValue>
      <KeyInfo>
        <KeyValue>
          <RSAKeyValue>
            <Modulus>
              1b+m37u3Xyawh2ArV8txLei251p03CXbkVuWaJu9C8eHy1pu87bcthi+T5WdlCPKD7KGtkKn9vq
              i4BJBZcG/Y10e8KWVlXDLg9gibN5hb0Agae3i1cCJTqqnQ0Ka8w1XABtbxTimS1B0aO1zYW6d+U
              Yl0xIeAOPsGMfWeu1NgLChZQton1/NrJsKwzMaQy1VI8m4gUleit9Z8mbz9bNMshdgYEZ9oC4bH
              n/SnA4FvQl1fjWyTpzL/aWF/bEzS6Qd8IBk7yhcWRJAGdXTWtwiX4mXb4h/2sdrSNvyOsd/shCf
              OSMsf0TX+OdlbH079AsxOwoUjlzjuKdCiFPdU6yAJw==
            </Modulus>
            <Exponent>Iw==</Exponent>
          </RSAKeyValue>
        </KeyValue>
      </KeyInfo>
    </Signature>
  </foo>

=head1 SEE ALSO

L<http://www.w3.org/TR/xmldsig-core/>

=head1 VERSION CONTROL

L<https://github.com/perl-net-saml2/perl-XML-Sig>

=head1 AUTHORS and CREDITS

Author: Byrne Reese <byrne@majordojo.com>

Thanks to Manni Heumann who wrote Google::SAML::Response from
which this module borrows heavily in order to create digital
signatures.

Net::SAML2 embedded version amended by Chris Andrews <chris@nodnol.org>.

Maintainer: Timothy Legge <timlegge@cpan.org>

=cut
