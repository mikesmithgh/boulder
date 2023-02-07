"""
A simple client that uses the Python ACME library to run a test issuance against
a local Pebble server. Unlike chisel.py this version implements the most recent
version of the ACME specification. Usage:

$ virtualenv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
$ python chisel.py foo.com bar.com
"""
from __future__ import print_function
from cryptography.hazmat.bindings._rust import (
    ObjectIdentifier as ObjectIdentifier,
)
from acme import standalone
from acme import messages
from acme import crypto_util as acme_crypto_util
from acme import client as acme_client
from acme import challenges
import josepy
import OpenSSL
from cryptography.hazmat.primitives.asymmetric import rsa
import requests
import logging
import os
import sys
import signal
import threading
import time
import string
import random
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from acme import crypto_util
import asn1
import subprocess


logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(int(os.getenv("LOGLEVEL", 0)))

# DIRECTORY = os.getenv('DIRECTORY', 'https://localhost:14000/dir')
DIRECTORY = os.getenv("DIRECTORY", "http://localhost:4001/directory")
# ACCEPTABLE_TOS = os.getenv('ACCEPTABLE_TOS',"data:text/plain,Do%20what%20thou%20wilt")
ACCEPTABLE_TOS = os.getenv(
    "ACCEPTABLE_TOS", "https://boulder.service.consul:4431/terms/v7"
)
PORT = os.getenv("PORT", "5002")

# URLs to control dns-test-srv
SET_TXT = "http://localhost:8055/set-txt"
CLEAR_TXT = "http://localhost:8055/clear-txt"

# https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#smi-numbers-1.3.6.1.5.5.7.1
TN_AUTH_LIST_OID = ObjectIdentifier("1.3.6.1.5.5.7.1.26")

IDENTIFIER_TN_AUTH_LIST = messages.IdentifierType(
    "TNAuthList"
)  # IdentifierTNAuthList in Boulder


class ShakenClientV2(acme_client.ClientV2):
    def new_order_shaken(self, csr_pem: bytes) -> messages.OrderResource:
        """Request a new Order object from the server.

        :param bytes csr_pem: A CSR in PEM format.

        :returns: The newly created order.
        :rtype: OrderResource
        """
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr_pem
        )

        # pylint: disable=protected-access
        dnsNames = crypto_util._pyopenssl_cert_or_req_all_names(csr)
        # ipNames is now []string
        identifiers = []

        for extension in csr.get_extensions():
            if extension.get_short_name().decode() == 'UNDEF':
                decoder = asn1.Decoder()
                decoder.start(extension.get_data())
                decoder.enter()
                tag, service_provider_code = decoder.read()
                decoder.leave()
                identifiers.append(
                    messages.Identifier(typ=IDENTIFIER_TN_AUTH_LIST, value=service_provider_code)
                )

        order = messages.NewOrder(identifiers=identifiers)
        response = self._post(self.directory["newOrder"], order)
        body = messages.Order.from_json(response.json())
        authorizations = []
        # pylint has trouble understanding our josepy based objects which use
        # things like custom metaclass logic. body.authorizations should be a
        # list of strings containing URLs so let's disable this check here.
        for url in body.authorizations:  # pylint: disable=not-an-iterable
            authorizations.append(
                self._authzr_from_response(self._post_as_get(url), uri=url)
            )
        return messages.OrderResource(
            body=body,
            uri=response.headers.get("Location"),
            authorizations=authorizations,
            csr_pem=csr_pem,
        )


def wait_for_acme_server():
    """Wait for directory URL set in the DIRECTORY env variable to respond"""
    while True:
        try:
            if requests.get(DIRECTORY).status_code == 200:
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(0.1)


def make_client(email=None):
    """Build an acme.Client and register a new account with a random key."""
    key = josepy.JWKRSA(key=rsa.generate_private_key(65537, 2048, default_backend()))

    net = acme_client.ClientNetwork(key, user_agent="Boulder integration tester")
    directory = messages.Directory.from_json(net.get(DIRECTORY).json())
    client = ShakenClientV2(directory, net)
    tos = client.directory.meta.terms_of_service
    if tos == ACCEPTABLE_TOS:
        net.account = client.new_account(
            messages.NewRegistration.from_data(
                email=email, terms_of_service_agreed=True
            )
        )
    else:
        raise Exception("Unrecognized terms of service URL %s" % tos)
    return client


def get_chall(authz, typ):
    for chall_body in authz.body.challenges:
        if isinstance(chall_body.chall, typ):
            return chall_body
    raise Exception("No %s challenge found" % typ)


class ValidationError(Exception):
    """An error that occurs during challenge validation."""

    def __init__(self, domain, problem_type, detail, *args, **kwargs):
        self.domain = domain
        self.problem_type = problem_type
        self.detail = detail

    def __str__(self):
        return "%s: %s: %s" % (self.domain, self.problem_type, self.detail)


def make_csr(domains):
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    return acme_crypto_util.make_csr(pem, domains, False)


def http_01_answer(client, chall_body):
    """Return an HTTP01Resource to server in response to the given challenge."""
    response, validation = chall_body.response_and_validation(client.net.key)
    return standalone.HTTP01RequestHandler.HTTP01Resource(
        chall=chall_body.chall, response=response, validation=validation
    )


def auth_and_issue(
    domains, chall_type="http-01", email=None, cert_output=None, client=None
):
    """Make authzs for each of the given domains, set up a server to answer the
    challenges in those authzs, tell the ACME server to validate the challenges,
    then poll for the authzs to be ready and issue a cert."""
    if client is None:
        client = make_client(email)

    csr_pem = make_csr(domains)
    order = client.new_order(csr_pem)
    authzs = order.authorizations

    if chall_type == "http-01":
        cleanup = do_http_challenges(client, authzs)
    elif chall_type == "dns-01":
        cleanup = do_dns_challenges(client, authzs)
    else:
        raise Exception("invalid challenge type %s" % chall_type)

    try:
        order = client.poll_and_finalize(order)
    finally:
        cleanup()

    return order


def print_pem(pem_data):
    print(pem_data.decode())


def pretty_print_csr(pem_data, no_out=True):
    temp_file = open("./chisel.csr.test.pem", "wb")
    temp_file.write(pem_data)
    temp_file.close()
    noout = ["-noout"] if no_out else []
    # assumption openssl cli installed
    subprocess.check_call(
        ["openssl", "req", "-text", "-in", "./chisel.csr.test.pem"] + noout
    )


def auth_and_issue_shaken(
    service_provider_code,
    chall_type="tkauth-01",
    email=None,
    client=None,
):
    """Make authzs for each of the given domains, set up a server to answer the
    challenges in those authzs, tell the ACME server to validate the challenges,
    then poll for the authzs to be ready and issue a cert."""
    if client is None:
        client = make_client(email)

    csr_pem, key_pem = make_csr_shaken(service_provider_code)
    pretty_print_csr(csr_pem)

    order = client.new_order_shaken(csr_pem)
    authzs = order.authorizations

    if chall_type == "tkauth-01":
        cleanup = do_http_challenges(client, authzs)  # TODO: update to tkauth
    else:
        raise Exception("invalid challenge type %s" % chall_type)

    try:
        order = client.poll_and_finalize(order)
    finally:
        cleanup()

    return order


def make_csr_shaken(service_provider_code):
    private_key = ec.generate_private_key(
        ec.SECP256R1, default_backend()
    )  # also known as p256

    subject_name = x509.Name(
        [
            # TODO: are we expecting any inalid characters in common name?
            x509.NameAttribute(NameOID.COMMON_NAME, "SHAKEN " + service_provider_code),
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
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(
        service_provider_code, asn1.Numbers.IA5String, None, asn1.Classes.Universal
    )
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

    csr_pem = builder.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return (csr_pem, key_pem)


def do_dns_challenges(client, authzs):
    cleanup_hosts = []
    for a in authzs:
        c = get_chall(a, challenges.DNS01)
        name, value = (
            c.validation_domain_name(a.body.identifier.value),
            c.validation(client.net.key),
        )
        cleanup_hosts.append(name)
        # Skip, this is pebble specific to add DNS record
        requests.post(
            SET_TXT, json={"host": name + ".", "value": value}
        ).raise_for_status()
        client.answer_challenge(c, c.response(client.net.key))

    def cleanup():
        for host in cleanup_hosts:
            # Skip, this is pebble specific to clear DNS record
            requests.post(CLEAR_TXT, json={"host": host + "."}).raise_for_status()

    return cleanup


def do_http_challenges(client, authzs):
    port = int(PORT)
    challs = [get_chall(a, challenges.HTTP01) for a in authzs]
    answers = set([http_01_answer(client, c) for c in challs])
    server = standalone.HTTP01Server(("", port), answers)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    # cleanup has to be called on any exception, or when validation is done.
    # Otherwise the process won't terminate.
    def cleanup():
        server.shutdown()
        server.server_close()
        thread.join()

    try:
        # Loop until the HTTP01Server is ready.
        while True:
            try:
                if requests.get("http://localhost:{0}".format(port)).status_code == 200:
                    break
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(0.1)

        for chall_body in challs:
            print(chall_body.chall.path)
            client.answer_challenge(chall_body, chall_body.response(client.net.key))
    except Exception:
        cleanup()
        raise

    return cleanup


def expect_problem(problem_type, func):
    """Run a function. If it raises a ValidationError or messages.Error that
    contains the given problem_type, return. If it raises no error or the wrong
    error, raise an exception."""
    ok = False
    try:
        func()
    except ValidationError as e:
        if e.problem_type == problem_type:
            ok = True
        else:
            raise
    except messages.Error as e:
        if problem_type in e.__str__():
            ok = True
        else:
            raise
    if not ok:
        raise Exception("Expected %s, got no error" % problem_type)


if __name__ == "__main__":
    # Die on SIGINT
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        hostname_length = 7
        random_host = [
            "".join(
                random.choices(
                    string.ascii_lowercase + string.digits, k=hostname_length
                )
            )
            + ".com"
        ]
        # wait_for_acme_server()
        # # dns challenge test
        # auth_and_issue(
        #     random_host, chall_type="dns-01", email=None, cert_output=None, client=None
        # )  # DNS
        # # http challenge
        # auth_and_issue(
        #     random_host, chall_type="http-01", email=None, cert_output=None, client=None
        # )  # DNS

        # "tkauth-01"  # SPC Token TKAuth

        csr, _ = make_csr_shaken("1234")
        pretty_print_csr(csr)
        # auth_and_issue_shaken("1234")
    except messages.Error as e:
        print(e)
        sys.exit(1)
