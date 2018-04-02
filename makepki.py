#!/usr/bin/env python3
# Make PKI from config file
# Sample config file at example.conf in the directory
import sys
import yaml
import logging
import socket
import copy
import os
import random
import string
from OpenSSL import crypto
import uuid
import pkitools


_ONE_DAY_IN_SEC = 60 * 60 * 24
_SUBJECT_FIELDS = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress']


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

    crt.set_pubkey(ca_key)
    crt.sign(ca_key, 'sha256')
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
    req.sign(key, 'sha256')

    # Sign CSR and make crt
    crt = crypto.X509()
    crt.set_version(2)
    crt.set_serial_number(int(uuid.uuid4()))  # all certs now get a random serial number

    crt.set_subject(req.get_subject())
    crt.set_issuer(ca_crt.get_subject())

    # Add custom extensions
    exts = set()
    if 'extension' in fields:
        for ext in fields['extension']:
            parts = ext.split('=')
            k = parts[0]
            v = parts[1]
            crt.add_extensions([crypto.X509Extension(k.encode('utf-8'), False, v.encode('utf-8'))])  # set required = False
            exts.add(k)

    # Set default extensions for all non-CA certs, if they don't conflict w/ above
    if 'basicConstraints' not in exts:
        crt.add_extensions([crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE')])
    if 'keyUsage' not in exts:
        crt.add_extensions([crypto.X509Extension(b'keyUsage', True, b'nonRepudiation, digitalSignature, keyEncipherment')])
    if 'subjectKeyIdentifier' not in exts:
        crt.add_extensions([crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=crt)])
    if 'authorityKeyIdentifier' not in exts:
        crt.add_extensions([crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid', issuer=ca_crt)])

    # Set subject alternative name to FQDN
    # TODO: Right now, this overrides any custom list above?
    san = 'DNS:{}'.format(fields['CN'])
    crt.add_extensions([crypto.X509Extension(b'subjectAltName', False, san.encode('utf-8'))])

    crt.gmtime_adj_notBefore(0)
    crt.gmtime_adj_notAfter(fields['lifetime'] * _ONE_DAY_IN_SEC)

    crt.set_pubkey(key)
    crt.sign(ca_key, 'sha256')

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
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(N))


def main():
    # Load config file cmd arg
    if len(sys.argv) < 2:
        raise Exception('No input file specified')

    # Set logging
    logging.basicConfig(level=logging.INFO)

    # Necessary boilerplate
    logging.warning("Warning: This script is for testing purposes only (for now). Private keys aren't encrypted.")

    # Useful host and domain information
    this_host = socket.gethostname()
    this_fqdn = socket.getfqdn()
    this_domain = this_fqdn[::-1].rsplit('.',1)[0][::-1]

    filename = sys.argv[1]
    with open(filename, 'r') as f:
        doc = yaml.load(f)

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
    common['lifetime'] = LIFETIME

    # Process hosts
    if 'hosts' not in doc:
        raise ValueError('hosts list not in doc')
    hosts = doc['hosts']

    # Make directory to hold results
    logging.info('All generated PKI files will be in directory: {}'.format(DOMAIN))
    if os.path.exists(DOMAIN):
        logging.warning('Directory {} already exists. This script will overwrite its contents if any filename matches.'.format(DOMAIN))
    else:
        os.makedirs(DOMAIN)

    # Make CA key
    logging.info('Making CA private key...')
    ca_key = gen_key(KEYSIZE)
    write_private_key(ca_key, os.path.join(DOMAIN, 'ca.key'))

    # Make CA cert
    logging.info('Making CA certificate...')
    ca_crt = gen_ca(ca_key, **merge_dict(common, {'CN': 'ca'}))
    write_certificate(ca_crt, os.path.join(DOMAIN, 'ca.pem'))

    # Expand hosts with template strings and add to hosts
    for i in range(len(hosts)):
        host = hosts[i]
        if isinstance(host, str) and "[" in host:  # expanded hosts can't override anything
            hosts.extend(pkitools.expand(host))  # online extension is OK since we only iterate thru original entries
            hosts[i] = None

    # Make host certificates
    logging.info('Making host certificates...')
    for host in hosts:
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

            fields = merge_dict(common, extra_fields)

        else:
            raise ValueError('host is not a str or dict')

        hostname = fields['hostname']
        fields['CN'] = '{}.{}'.format(hostname, DOMAIN)  # SAN extension is also set. It's supposed to ignore this...

        logging.info("Making {}'s private key...".format(hostname))
        key = gen_key(KEYSIZE)
        write_private_key(key, os.path.join(DOMAIN, '{}.key'.format(hostname)))

        logging.info("Making and signing {}'s certificate...".format(hostname))
        crt = sign_key(key, ca_key, ca_crt, **fields)
        write_certificate(crt, os.path.join(DOMAIN, '{}.pem'.format(hostname)))

        # Combine key, cert, and CA cert into a pkcs12 WITHOUT a password file if desired
        #   Keeps the individual files around
        if 'combine_pkcs12' in common_options:
            p12 = crypto.PKCS12()
            p12.set_ca_certificates([ca_crt])
            p12.set_certificate(crt)
            p12.set_privatekey(key)
            password = random_string(16)  # generate random password because it's required for import
            p12filename = os.path.join(DOMAIN, '{}.p12'.format(hostname))
            logging.warning('Password {} generated for {}'.format(password, p12filename))
            with open(p12filename, 'wb') as f:
                f.write(p12.export(passphrase=password))

    logging.info('done.')


if __name__ == '__main__':
    main()
