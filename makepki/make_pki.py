"""Make PKI from config file
Sample config file at example.conf in the directory
"""
import os
import sys
import copy
import uuid
import yaml
import string
import socket
import logging
import secrets
from OpenSSL import crypto

from makepki.pkitools import expand

log = logging.getLogger(__name__)

this_dir = os.path.dirname(os.path.realpath(__file__))

_ONE_DAY_IN_SEC = 60 * 60 * 24
_SUBJECT_FIELDS = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress']
SIGN_HASH = 'sha256'


def gen_key(size=2048):
    """Make an RSA private key

    Args:
        size: int, size of key in bytes. Min size = 2048.

    Returns:
        PKey obj, private key
    """
    if size < 2048:
        raise ValueError('Key must be >= 2048 bytes')

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, size)
    return key


def read_private_key(filename, passphrase=None):
    """Read private key with PEM encoding

    Args:
        filename: str location of key file
        passphrase: str passphrase to decrypt key

    Returns:
        PKey obj, private key
    """
    with open(filename, 'rb') as f:
        return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), passphrase=passphrase)


def write_private_key(key, filename, passphrase=None):
    """Write key to file using usual PEM encoding, optionally encrypted with passphrase

    Args:
        key: PKey obj, private key
        filename: str location to save file
        passphrase: str passphrase to encrypt key
    """
    with open(filename, 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, passphrase=passphrase))


def write_certificate(crt, filename):
    """Write certificate to file using usual PEM encoding.

    Args:
        X509 obj, certificate
        filename: str location to save file
    """
    with open(filename, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))


def read_certificate(filename):
    """Read certificate from file using PEM encoding

    Args:
        filename: str path to certificace

    Returns:
        X509 obj, certificate
    """
    with open(filename, 'rb') as f:
        return crypto.load_certificate(crypto.FILETYPE_PEM, f.read())


def gen_ca(ca_key, **fields):
    """Create CA authority/cert. No intermediate CAs can be made under this.

    Args:
        ca_key: PKey obj, CA private key
        fields: named args dict of fields. TODO: Spec for what should be in here.

    Returns:
        X509 obj, CA certificate
    """
    crt = crypto.X509()
    crt.set_version(2)  # version 3, counts from 0
    crt.set_serial_number(1)
    crt.set_pubkey(ca_key)

    sub = crt.get_subject()
    for sub_field in _SUBJECT_FIELDS:
        if sub_field in fields:
            setattr(sub, sub_field, fields[sub_field])
    crt.set_issuer(sub)

    # CA extensions
    crt.add_extensions([
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
        crypto.X509Extension(b'keyUsage', True, b'keyCertSign, cRLSign'),
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=crt),
    ])

    crt.gmtime_adj_notBefore(0)
    crt.gmtime_adj_notAfter(fields['lifetime'] * _ONE_DAY_IN_SEC)

    crt.sign(ca_key, SIGN_HASH)
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

    # Make CSR
    req = crypto.X509Req()

    sub = req.get_subject()
    for sub_field in _SUBJECT_FIELDS:
        if sub_field in fields:
            setattr(sub, sub_field, fields[sub_field])

    req.set_pubkey(key)
    req.sign(key, SIGN_HASH)

    # Sign CSR and make crt
    crt = crypto.X509()
    crt.set_version(2)
    crt.set_serial_number(int(uuid.uuid4()))  # all certs now get a random serial number
    crt.set_pubkey(key)

    crt.set_subject(req.get_subject())
    crt.set_issuer(ca_crt.get_subject())

    # Add custom extensions
    exts = set()
    if 'extension' in fields:
        for ext in fields['extension']:
            parts = ext.split('=')
            k = parts[0]
            v = parts[1]
            crt.add_extensions(
                [crypto.X509Extension(k.encode('utf-8'), False, v.encode('utf-8'))])  # set required = False
            exts.add(k)

    # Set default extensions for all non-CA certs, if they don't conflict w/ above
    if 'basicConstraints' not in exts:
        crt.add_extensions([crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE')])
    if 'keyUsage' not in exts:
        crt.add_extensions(
            [crypto.X509Extension(b'keyUsage', True, b'nonRepudiation, digitalSignature, keyEncipherment')])
    if 'subjectKeyIdentifier' not in exts:
        crt.add_extensions([crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=crt)])
    if 'authorityKeyIdentifier' not in exts:
        crt.add_extensions([crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid', issuer=ca_crt)])

    # Set subject alternative name - required for modern SSL certificates
    #   If CN is a FQDN, use DNS entry; if CN is an IP address, use IP entry
    #   If subjectAltName is already set above, skip this
    if 'subjectAltName' not in exts:
        cn = fields['CN']
        if is_valid_ipv4_address(cn):
            san = 'IP:{}'.format(cn)
        else:
            san = 'DNS:{}'.format(cn)
        crt.add_extensions([crypto.X509Extension(b'subjectAltName', False, san.encode('utf-8'))])

    crt.gmtime_adj_notBefore(0)
    crt.gmtime_adj_notAfter(fields['lifetime'] * _ONE_DAY_IN_SEC)

    crt.sign(ca_key, SIGN_HASH)

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

    DOMAIN = common['domain']

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
            p12 = crypto.PKCS12()
            p12.set_ca_certificates([ca_crt])
            p12.set_certificate(crt)
            p12.set_privatekey(key)
            password = random_string(16)  # generate random password because it's required for import
            p12filename = os.path.join(output_dir, '{}.p12'.format(hostname))
            log.warning('Password {} generated for {}'.format(password, p12filename))
            with open(p12filename, 'wb') as f:
                f.write(p12.export(passphrase=password.encode('utf8')))

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
