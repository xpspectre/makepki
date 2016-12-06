#!/usr/bin/env python3
# Make PKI from config file
# Sample config file at example.conf in the directory

import sys
import yaml
import socket
import copy
import os
import random
import string
from subprocess import call
import pkitools

if len(sys.argv) < 2:
    raise Exception('No input file specified')

# Necessary boilerplate
print("Warning: This script is for testing purposes only (for now). Private keys aren't encrypted.")

# Useful host and domain information
this_host = socket.gethostname()
this_fqdn = socket.getfqdn()
this_domain = this_fqdn[::-1].rsplit('.',1)[0][::-1]

filename = sys.argv[1]
with open(filename, 'r') as f:
    doc = yaml.load(f)


def merge_dict(bot, top):
    """Helper function for merging dict fields over another dict.
    Merge top dict onto bot dict, so that the returned new dict has the updated top vals."""
    new = copy.deepcopy(bot)
    for k,v in top.items():
        new[k] = v
    return new


def random_string(N):
    """Make random string of letters and digits for temporary extension config file names"""
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(N))


def make_subject(fields):
    """Helper function for building the subject line for an X.509 CSR"""
    # Populate required fields
    subject = "/C=%(C)s/ST=%(ST)s/L=%(L)s/O=%(O)s/CN=%(hostname)s.%(domain)s" % fields

    # Populate optional fields
    if 'emailAddress' in fields:
        subject += "/emailAddress=%(emailAddress)s" % fields

    return subject


def make_extensions(fields):
    """Helper function for building an extension config file. The 'extension' field in fields can be either a string
    or a list (iterable) of strings."""
    if 'extension' in fields:
        config_file = os.path.join(DOMAIN, random_string(5) + '.conf')
        with open(config_file, 'w') as f:
            # f.write('[extensions]\n')
            vals = fields['extension']
            if isinstance(vals, list):
                for val in vals:
                    if not isinstance(val, str):
                        raise ValueError('Extension in list of extensions must be a string')
                    f.write("%s\n" % val)
            elif isinstance(vals, str):
                f.write("%s\n" % vals)
            else:
                raise ValueError('Extension must be a string or list of strings')
    else:
        config_file = None

    return config_file


def runcmd(cmd):
    """Helper function for debugging and running shell commands"""
    print('> ' + cmd)
    call(cmd, shell=True)


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
if 'keysize' in common_options:
    KEYSIZE = common_options['keysize']
else:
    KEYSIZE = 2048

if 'lifetime' in common_options:
    LIFETIME = common_options['lifetime']
else:
    LIFETIME = 365

# Process hosts
if 'hosts' not in doc:
    raise ValueError('hosts list not in doc')
hosts = doc['hosts']

# Make directory to hold results
print('All generated PKI files will be in directory: %s' % (DOMAIN,))
if os.path.exists(DOMAIN):
    print("Directory %s already exists. This script will overwrite its contents if any filename matches." % DOMAIN)
else:
    os.makedirs(DOMAIN)

# Make CA
print('Making CA private key...')
runcmd("openssl genrsa -out %s %d" % (os.path.join(DOMAIN, 'ca.key'), KEYSIZE))

# Make CA cert
print('Making CA certificate...')
ca_subject_fields = merge_dict(common, {'hostname': 'ca'})
ca_subject = make_subject(ca_subject_fields)
runcmd('openssl req -x509 -new -nodes -key %s -days %d -out %s -sha256 -subj "%s"' % (
        os.path.join(DOMAIN, 'ca.key'),
        LIFETIME,
        os.path.join(DOMAIN, 'ca.pem'),
        ca_subject))

# Delete existing serial to start clean
print('Deleting old serial (if it exists)...')
serial_file = os.path.join(DOMAIN, 'ca.srl')
if os.path.isfile(serial_file):
    os.remove(serial_file)

# Expand hosts with template strings and add to hosts
expandedHosts = []
for i in range(len(hosts)):
    host = hosts[i]
    if isinstance(host, str) and "[" in host:  # expanded hosts can't override anything
        hosts.extend(pkitools.expand(host))  # online extension is OK since we only iterate thru original entries
        hosts[i] = None

# Make host certificates
print('Making host certificates...')
ind = 1  # Index for serial number generation
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
    subject = make_subject(fields)
    extension_config_file = make_extensions(fields)

    print("Making %s's private key..." % (hostname,))
    runcmd("openssl genrsa -out %s %d" % (os.path.join(DOMAIN, '%s.key' % (hostname,)), KEYSIZE))

    print("Making %s's CSR..." % (hostname,))
    runcmd('openssl req -new -key %s -out %s -sha256 -subj "%s"' % (
        os.path.join(DOMAIN, '%s.key' % (hostname,)),
        os.path.join(DOMAIN, '%s.csr' % (hostname,)),
        subject))

    # The 1st CSR signed is used to generate a random serial
    print("Signing %s's certificate..." % (hostname,))
    if ind == 1:
        serial_string = '-CAcreateserial'
    else:
        serial_string = ''

    if extension_config_file is not None:
        extension_string = '-extfile %s' % extension_config_file
    else:
        extension_string = ''

    runcmd('openssl x509 -req -in %s -CA %s -CAkey %s %s -CAserial %s %s -out %s -days %d' % (
        os.path.join(DOMAIN, '%s.csr' % (hostname,)),
        os.path.join(DOMAIN, 'ca.pem'),
        os.path.join(DOMAIN, 'ca.key'),
        serial_string,
        serial_file,
        extension_string,
        os.path.join(DOMAIN, '%s.pem' % (hostname,)),
        LIFETIME))

    if extension_config_file is not None:  # Cleanup. If the above command fails, you can look at the config file.
        os.remove(extension_config_file)

    # Combine certs into pkcs12 format if desired
    # Also remove separate cert and key
    # TODO: add other options here as desired - for example, don't include the CA cert in there
    if 'combine_pkcs12' in common_options:
        COMBINE_MODE = common_options['combine_pkcs12']
        if COMBINE_MODE == 'all':
            runcmd('openssl pkcs12 -export -in %s -inkey %s -certfile %s -out %s -passout pass:' % (
                os.path.join(DOMAIN, '%s.pem' % (hostname,)),
                os.path.join(DOMAIN, '%s.key' % (hostname,)),
                os.path.join(DOMAIN, 'ca.pem'),
                os.path.join(DOMAIN, '%s.p12' % (hostname,)),
            ))
            os.remove(os.path.join(DOMAIN, '%s.pem' % (hostname,)))
            os.remove(os.path.join(DOMAIN, '%s.key' % (hostname,)))

    f_srl = open(serial_file)
    srl = f_srl.read()
    f_srl.close()
    print("%s's certificate has serial number %s..." % (hostname, srl))

    # Increment index for serial number generation
    ind += 1

print('done.')
