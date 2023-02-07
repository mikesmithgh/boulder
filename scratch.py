import OpenSSL
import ipaddress
from datetime import datetime, timedelta
from asn1crypto.core import ObjectIdentifier
import josepy
import asn1

#
# class MyType(ObjectIdentifier):
#     _map = {
#         "1.8.2.1.23": "value_name",
#         "1.8.2.1.24": "other_value",
#     }
#
#
# # Will print: "value_name"
# print(MyType("1.8.2.1.23").native)
#
# # Will print: "1.8.2.1.23"
# print(MyType("1.8.2.1.23").dotted)
#
# # Will print: "1.8.2.1.25"
# print(MyType("1.8.2.1.25").native)
#
# # Will print "value_name"
# print(MyType.map("1.8.2.1.23"))
#
# # Will print "1.8.2.1.23"
# print(MyType.unmap("value_name"))
#
#
# # https://gist.github.com/bloodearnest/9017111a313777b9cce5
# def generate_selfsigned_cert(hostname, ip_addresses=None, key=None):
#     """Generates self signed certificate for a hostname,
#     and optional IP addresses."""
#     from cryptography import x509
#     from cryptography.x509.oid import NameOID
#     from cryptography.x509.oid import ExtensionOID
#     from cryptography.hazmat.primitives import hashes
#     from cryptography.hazmat.backends import default_backend
#     from cryptography.hazmat.primitives import serialization
#     from cryptography.hazmat.primitives.asymmetric import rsa
#
#     # Generate our key
#     if key is None:
#         key = rsa.generate_private_key(
#             public_exponent=65537,
#             key_size=2048,
#             backend=default_backend(),
#         )
#
#     name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
#
#     # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
#     alt_names = [x509.DNSName(hostname)]
#
#     # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios
#     if ip_addresses:
#         for addr in ip_addresses:
#             # openssl wants DNSnames for ips...
#             alt_names.append(x509.DNSName(addr))
#             # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
#             # note: older versions of cryptography do not understand ip_address objects
#             alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
#
#     san = x509.SubjectAlternativeName(alt_names)
#
#     # path_len=0 means this cert can only sign itself, not other certs.
#     basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
#     now = datetime.utcnow()
#     cert = (
#         x509.CertificateBuilder()
#         .subject_name(name)
#         .issuer_name(name)
#         .public_key(key.public_key())
#         .serial_number(1000)
#         .not_valid_before(now)
#         .not_valid_after(now + timedelta(days=10 * 365))
#         .add_extension(basic_contraints, False)
#         .add_extension(san, False)
#         .sign(key, hashes.SHA256(), default_backend())
#     )
#     cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
#     key_pem = key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.TraditionalOpenSSL,
#         encryption_algorithm=serialization.NoEncryption(),
#     )
#
#     return cert_pem, key_pem
#
#
# (c, k) = generate_selfsigned_cert("foo.com")
# print(c)
# print(k)
#
# # key = OpenSSL.crypto.PKey()
# # key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
# # pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
# # return acme_crypto_util.make_csr(pem, domains, False)
#
# OpenSSL.crypto.PKey()


def generateCsr(service_provider_code="1234"):

    from cryptography import x509

    from cryptography.hazmat.bindings._rust import x509 as rust_x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    # https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.1
    TN_AUTH_LIST_OID = ObjectIdentifier("1.3.6.1.5.5.7.1.26")

    class TNAuthList(x509.ExtensionType):
        oid = TN_AUTH_LIST_OID

        def __init__(self, service_provider_code: str) -> None:
            self._tn_entry = {"ServiceProviderCode": service_provider_code}

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, TNAuthList):
                return NotImplemented

            return self.tn_entry == other.tn_entry

        def __hash__(self) -> int:
            return hash(self.tn_entry)

        def __repr__(self) -> str:
            return f"<TNAuthList({self.tn_entry})>"

        @property
        def tn_entry(self) -> str:
            return self._tn_entry

        def public_bytes(self) -> bytes:
            return rust_x509.encode_extension_value(self)

    private_key = ec.generate_private_key(
        ec.SECP256R1, default_backend()
    )  # also known as p256
    # TODO: tnentry

    # san = x509.SubjectAlternativeName(alt_names)
    #
    # # path_len=0 means this cert can only sign itself, not other certs.
    # basic_contraints = x509.BasicConstraints(ca=True, path_length=0)

    subject_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME,
                               "SHAKEN " + service_provider_code),
            # x509.NameAttribute(NameOID.COMMON_NAME, "SHAKEN"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pennsylvania"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Philadelphia"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example CA"),
        ]
    )

    relative_distinguished_name = x509.RelativeDistinguishedName(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "SHAKEN Root CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pennsylvania"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Philadelphia"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example CA"),
        ]
    )

    distribution_points = x509.DistributionPoint(
        [x509.UniformResourceIdentifier("https://sti-pa.com/shaken/crl")],
        None,
        None,
        None,
    )
    # x509.GeneralNames([relative_distinguished_name]),
    # x509.DirectoryName("CN=STI-PA CRL,O=STI-PA,C=US"),
    encoder = asn1.Encoder()
    encoder.start()
    # encoder.write("tn_auth_list", asn1.Numbers.Sequence)
    # encoder.write("1.3.6.1.5.5.7.1", asn1.Numbers.ObjectIdentifier)
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write("1234", asn1.Numbers.IA5String, None, asn1.Classes.Universal)
    encoder.leave()
    encoded_bytes = encoder.output()

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject_name)
        .add_extension(
            x509.extensions.CRLDistributionPoints([distribution_points]), True
        )
        .add_extension(
            x509.UnrecognizedExtension(TN_AUTH_LIST_OID, encoded_bytes),
            True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # # TODO add this
    #             x509.UnrecognizedExtension(
    #                 x509.ObjectIdentifier("1.2.3.4.5"),
    #                 b"abcdef",
    #             )
    #         ]

    cert_pem = builder.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    print(cert_pem)
    print(key_pem)
    f = open("/Users/mike/tmp/tmp.csr.pem", "wb")
    f.write(cert_pem)
    f.close()


generateCsr("1234")
