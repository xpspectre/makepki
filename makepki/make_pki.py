"""Make PKI from config file
Sample config file at example.conf in the directory
"""
import os
import sys
import copy
import yaml
import string
import socket
import logging
import secrets
import ipaddress
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates

from makepki.pkitools import expand

log = logging.getLogger(__name__)

this_dir = os.path.dirname(os.path.realpath(__file__))

SUBJECT_FIELDS = {
    'C': NameOID.COUNTRY_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,
    'L': NameOID.LOCALITY_NAME,
    'O': NameOID.ORGANIZATION_NAME,
    'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'CN': NameOID.COMMON_NAME,
    'emailAddress': NameOID.EMAIL_ADDRESS,
}
EXTENSION_FIELDS = {
    'keyUsage': x509.KeyUsage,
    'extendedKeyUsage': x509.ExtendedKeyUsage,
}
KEY_USAGE = {
    'digitalSignature': 'digital_signature',
    'contentCommitment': 'content_commitment',  # aka nonRepudiation
    'keyEncipherment': 'key_encipherment',
    'dataEncipherment': 'data_encipherment',
    'keyCertSign': 'key_cert_sign',
    'cRLSign': 'crl_sign',
    'keyAgreement': 'key_agreement',
    'encipherOnly': 'encipher_only',
    'decipherOnly': 'decipher_only',
}
DEFAULT_KEY_USAGE_KWARGS = {val: False for val in KEY_USAGE.values()}
EXTENDED_KEY_USAGE = {
    'serverAuth': ExtendedKeyUsageOID.SERVER_AUTH,
    'clientAuth': ExtendedKeyUsageOID.CLIENT_AUTH,
    'codeSigning': ExtendedKeyUsageOID.CODE_SIGNING,
    'emailProtection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
    'timeStamping': ExtendedKeyUsageOID.TIME_STAMPING,
    'OCSPSigning': ExtendedKeyUsageOID.OCSP_SIGNING,
    'ipsecIKE': ExtendedKeyUsageOID.IPSEC_IKE,
    'anyExtendedUsage': ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
}
ONE_YEAR = timedelta(days=365)


def gen_key(size=2048):
    """Make an RSA private key

    Args:
        size: int, size of key in bytes. Min size = 2048.
    """
    if size < 2048:
        raise ValueError('Key must be >= 2048 bytes')

    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def read_private_key(filename, passphrase=None):
    """Read private key with PEM encoding

    Args:
        filename: str location of key file
        passphrase: str passphrase to decrypt key
    """
    with open(filename, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase)


def write_private_key(key, filename, passphrase=None):
    """Write key to file using usual PEM encoding, optionally encrypted with passphrase

    Args:
        key: PKey obj, private key
        filename: str location to save file
        passphrase: str passphrase to encrypt key
    """
    kwargs = {
        'encoding': serialization.Encoding.PEM,
        'format': serialization.PrivateFormat.TraditionalOpenSSL
    }
    if passphrase is None:
        kwargs['encryption_algorithm'] = serialization.NoEncryption()
    else:
        kwargs['encryption_algorithm'] = serialization.BestAvailableEncryption(passphrase)
    pem = key.private_bytes(**kwargs)
    with open(filename, 'wb') as f:
        f.write(pem)


def write_certificate(crt, filename):
    """Write certificate to file using usual PEM encoding.

    Args:
        X509 obj, certificate
        filename: str location to save file
    """
    with open(filename, 'wb') as f:
        f.write(crt.public_bytes(serialization.Encoding.PEM))


def read_certificate(filename):
    """Read certificate from file using PEM encoding

    Args:
        filename: str path to certificace

    Returns:
        X509 obj, certificate
    """
    with open(filename, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())


def gen_ca(ca_key, **fields):
    """Create CA cert from an existing private key. No intermediate CAs can be made under this.

    Args:
        ca_key: PKey obj, CA private key
        fields: named args dict of fields. TODO: Spec for what should be in here.

    Returns:
        X509 obj, CA certificate
    """
    ca_pubkey = ca_key.public_key()

    builder = x509.CertificateBuilder()

    name = []
    for key, val in SUBJECT_FIELDS.items():
        if key not in fields:
            continue
        name.append(x509.NameAttribute(val, fields[key]))
    builder = builder.subject_name(x509.Name(name))
    builder = builder.issuer_name(x509.Name(name))

    now = datetime.now()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + ONE_YEAR)

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ca_pubkey)

    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    builder = builder.add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True,
                                                  digital_signature=False, content_commitment=False,
                                                  key_encipherment=False, data_encipherment=False,
                                                  key_agreement=False, encipher_only=False, decipher_only=False),
                                    critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_pubkey), critical=False)

    crt = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crt


def sign_key(key, ca_key, ca_crt, **fields):
    """Create a certificate signing request for a client with key, and sign with CA key and info.

    Args:
        key: PKey obj, client private key
        ca_key: PKey obj, CA private key
        ca_crt: X509 obj, CA certificate
        fields: see gen_ca()'s fields arg

    Returns:
        X509 obj, signed client certificate
    """
    pubkey = key.public_key()
    ca_pubkey = ca_key.public_key()

    builder = x509.CertificateBuilder()

    name = []
    for key, val in SUBJECT_FIELDS.items():
        if key not in fields:
            continue
        name.append(x509.NameAttribute(val, fields[key]))
    builder = builder.subject_name(x509.Name(name))

    builder = builder.issuer_name(ca_crt.issuer)

    now = datetime.now()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + ONE_YEAR)

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pubkey)

    exts = set()

    # Set specified extensions
    if 'extension' in fields:
        for ext in fields['extension']:
            parts = ext.split('=')
            assert len(parts) == 2
            name, val = parts
            extension = EXTENSION_FIELDS[name]
            if extension == x509.KeyUsage:
                kwargs = {**DEFAULT_KEY_USAGE_KWARGS}
                for usage in [usage.strip() for usage in val.split(',')]:
                    kwargs[KEY_USAGE[usage]] = True
                builder = builder.add_extension(x509.KeyUsage(**kwargs), critical=True)
            elif extension == x509.ExtendedKeyUsage:
                usages = []
                for usage in [usage.strip() for usage in val.split(',')]:
                    usages.append(EXTENDED_KEY_USAGE[usage])
                builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
            else:
                raise ValueError(f'Extension {extension} not handled')  # looking up in EXTENSION_FIELDS should fail
            exts.add(name)

    # Set default extensions for all non-CA certs, if they don't conflict w/ above
    if 'basicConstraints' not in exts:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    if 'keyUsage' not in exts:
        builder = builder.add_extension(x509.KeyUsage(key_cert_sign=False, crl_sign=False,
                                                      digital_signature=True, content_commitment=False,
                                                      key_encipherment=True, data_encipherment=False,
                                                      key_agreement=False, encipher_only=False, decipher_only=False),
                                        critical=True)

    if 'subjectKeyIdentifier' not in exts:
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(pubkey), critical=False)

    if 'authorityKeyIdentifier' not in exts:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pubkey), critical=False)

    # Set subject alternative name - required for modern SSL certificates
    #   If CN is a FQDN, use DNS entry; if CN is an IP address, use IP entry
    #   If subjectAltName is already set above, skip this
    if 'subjectAltName' not in exts:
        cn = fields['CN']
        if is_valid_ipv4_address(cn):
            san = x509.IPAddress(ipaddress.IPv4Address(cn))
        else:
            san = x509.DNSName(cn)
        builder = builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)

    crt = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crt


def merge_dict(bot, top):
    """Helper function for merging dict fields over another dict.
    Merge top dict onto bot dict, so that the returned new dict has the updated top vals."""
    new = copy.deepcopy(bot)
    for k, v in top.items():
        new[k] = v
    return new


def random_string(N):
    """Make random string of letters and digits"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(N))


def is_valid_ipv4_address(address):
    """Check if address str is a valid IPv4 address (with all parts)"""
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False


def build(doc, output_base_dir):
    # Useful host and domain information
    this_host = socket.gethostname()
    this_fqdn = socket.getfqdn()
    this_domain = this_fqdn[::-1].rsplit('.', 1)[0][::-1]

    # Process required common fields
    if 'common' not in doc:
        raise Exception('common fields not in doc')
    common = doc['common']
    common_options = common.pop('options', {})

    # Process common options
    if 'localdomain' in common_options and common_options['localdomain'] is True:
        common['domain'] = this_domain

    DOMAIN: str = common['domain']

    # Default options
    KEYSIZE = common_options.get('keysize', 2048)  # in bytes
    LIFETIME = common_options.get('lifetime', 365)  # in days
    CACN = common_options.get('cacn', 'ca')
    common['lifetime'] = LIFETIME

    # Process hosts
    if 'hosts' not in doc:
        raise ValueError('hosts list not in doc')
    hosts = doc['hosts']

    # Make directory to hold results
    output_dir = os.path.join(output_base_dir, DOMAIN)
    log.info('All generated PKI files will be in directory: {}'.format(output_dir))
    if os.path.exists(output_dir):
        log.warning(
            'Directory {} already exists. This script will overwrite its contents if any filename matches.'.format(
                output_dir))
    else:
        os.makedirs(output_dir)

    # Determine whether we're generating a new CA or loading an existing one
    cakey_file = os.path.join(output_dir, 'ca.key')
    cacrt_file = os.path.join(output_dir, 'ca.pem')
    if 'cacrt' in doc and 'cakey' in doc:  # load exising ca
        # TODO: Right now, this assumes the CA key and crt are the same form as output by this function;
        #   we can actually use the value in those fields (relative to this config) as well
        log.info('Loading CA private key...')
        ca_key = read_private_key(cakey_file)

        log.info('Loading CA certificate...')
        ca_crt = read_certificate(cacrt_file)
    else:
        # Make CA key
        log.info('Making CA private key...')
        ca_key = gen_key(KEYSIZE)
        write_private_key(ca_key, cakey_file)

        # Make CA cert
        log.info('Making CA certificate...')
        ca_crt = gen_ca(ca_key, **merge_dict(common, {'CN': CACN}))
        write_certificate(ca_crt, cacrt_file)

    # Expand hosts with template strings and add to hosts
    for i in range(len(hosts)):
        host = hosts[i]
        if isinstance(host, str) and '[' in host:  # expanded hosts can't override anything
            hosts.extend(expand(host))  # online extension is OK since we only iterate thru original entries
            hosts[i] = None

    # Make host certificates
    log.info('Making host certificates...')
    for host in hosts:
        nodomain = False  # whether to suppress appending domain to hostname to form CN and SAN

        if host is None:  # skip holes from template interpolation
            continue

        elif isinstance(host, str):  # Use all default fields + hostname
            fields = merge_dict(common, {'hostname': host})

        elif isinstance(host, dict):  # Overwrite some fields
            for k in host:  # Assign name of struct into a field where it can be processed; there should just be the one iteration
                hostname = k
            extra_fields = host[hostname]
            extra_fields['hostname'] = hostname

            options = extra_fields.pop('options', {})
            if 'localhost' in options and options['localhost'] is True:
                extra_fields['hostname'] = this_host
            if 'localdomain' in options and options['localdomain'] is True:
                extra_fields['domain'] = this_domain
            if 'extension' in options:  # Arbitrary extra extensions
                extra_fields['extension'] = options['extension']

            if 'nodomain' in options and options['nodomain'] is True:
                nodomain = True

            fields = merge_dict(common, extra_fields)

        else:
            raise ValueError('host is not a str or dict')

        hostname = fields['hostname']
        if nodomain:
            fields['CN'] = hostname
        else:
            fields['CN'] = '{}.{}'.format(hostname, fields['domain'])

        log.info("Making {}'s private key...".format(hostname))
        key = gen_key(KEYSIZE)
        write_private_key(key, os.path.join(output_dir, '{}.key'.format(hostname)))

        log.info("Making and signing {}'s certificate...".format(hostname))
        crt = sign_key(key, ca_key, ca_crt, **fields)
        write_certificate(crt, os.path.join(output_dir, '{}.pem'.format(hostname)))

        # Combine key, cert, and CA cert into a pkcs12 WITHOUT a password file if desired
        #   Keeps the individual files around
        if 'combine_pkcs12' in common_options:
            password = random_string(16)  # generate random password because it's required for import
            content = serialize_key_and_certificates(fields['CN'].encode('utf8'), key, crt, [ca_crt],
                                                     serialization.BestAvailableEncryption(password.encode('utf8')))
            p12filename = os.path.join(output_dir, '{}.p12'.format(hostname))
            log.warning('Password {} generated for {}'.format(password, p12filename))
            with open(p12filename, 'wb') as f:
                f.write(content)

    log.info('done.')


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s : %(asctime)s : %(name)s : %(message)s')

    # Necessary boilerplate
    log.warning("Warning: This script is for testing purposes only (for now). Private keys aren't encrypted.")

    # Load config file cmd arg
    if len(sys.argv) < 2:
        raise Exception('No input file specified')

    filename = sys.argv[1]
    with open(filename, 'r') as f:
        doc = yaml.safe_load(f)

    # Make sure output directory is present
    output_base_dir = os.path.join(this_dir, '../output')
    if not os.path.exists(output_base_dir):
        os.makedirs(output_base_dir)

    build(doc, output_base_dir)


if __name__ == '__main__':
    main()
