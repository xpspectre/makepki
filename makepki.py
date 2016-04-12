#!/usr/bin/env python3
# Make PKI from config file
# Sample config file at example.conf in the directory

import sys
import yaml
import socket
import copy
import os
import shutil
from subprocess import call

if len(sys.argv) < 2:
    raise Exception('No input file specified')

# Necessary boilerplate
print("Warning: this script is for testing purposes only (for now). Private keys aren't encrypted.")

# Useful host and domain information
this_host = socket.gethostname()
this_fqdn = socket.getfqdn()
this_domain = this_fqdn[::-1].rsplit('.',1)[0][::-1]

filename = sys.argv[1]
with open(filename, 'r') as f:
    doc = yaml.load(f)


# Helper function for merging dict fields over another dict
def merge_dict(bot, top):
    """Merge top dict onto bot dict, so that the returned new dict has the updated top vals"""
    new = copy.deepcopy(bot)
    for k,v in top.items():
        new[k] = v
    return new


# Helper function for building the subject line for an X.509 CSR
def make_subject(fields):
    # Populate required fields
    subject = "/C=%(C)s/ST=%(ST)s/L=%(L)s/O=%(O)s/CN=%(hostname)s.%(domain)s" % fields

    # Populate optional fields
    if 'emailAddress' in fields:
        subject += "/emailAddress=%(emailAddress)s" % fields

    return subject

# Helper function for debugging and running shell commands
def runcmd(cmd):
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
DOMAIN1 = DOMAIN.split('.',1)[0]  # left-most subdomain is used for serial number file

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
    raise Exception('hosts list not in doc')
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
serialFile = os.path.join(DOMAIN, 'ca.srl')
if os.path.isfile(serialFile):
    os.remove(serialFile)

# Make host certificates
print('Making host certificates...')
ind = 1
for host in hosts:

    if isinstance(host, str):  # Use all default fields + hostname
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

        fields = merge_dict(common, extra_fields)

    else:
        raise Exception('host is not a str or dict')

    hostname = fields['hostname']
    subject = make_subject(fields)

    print("Making %s's private key..." % (hostname,))
    runcmd("openssl genrsa -out %s %d" % (os.path.join(DOMAIN, '%s.key' % (hostname,)), KEYSIZE))

    print("Making %s's CSR..." % (hostname,))

    runcmd('openssl req -new -key %s -out %s -sha256 -subj "%s"' % (
        os.path.join(DOMAIN, '%s.key' % (hostname,)),
        os.path.join(DOMAIN, '%s.csr' % (hostname,)),
        subject))

    print("Making %s's certificate..." % (hostname,))
    if ind == 1:
        serialString = '-CAcreateserial'
    else:
        serialString = '-CAserial %s' % (serialFile,)

    runcmd('openssl x509 -req -in %s -CA %s -CAkey %s %s -out %s -days %d' % (
        os.path.join(DOMAIN, '%s.csr' % (hostname,)),
        os.path.join(DOMAIN, 'ca.pem'),
        os.path.join(DOMAIN, 'ca.key'),
        serialString,
        os.path.join(DOMAIN, '%s.pem' % (hostname,)),
        LIFETIME))

    # Move serial file to right place (since openssl always places it in the current directory
    if ind == 1:
        shutil.move('%s.srl' % (DOMAIN1,), serialFile)

    f_srl = open(serialFile)
    srl = f_srl.read()
    f_srl.close()
    print("%s's certificate has serial number %s..." % (hostname,srl))

    # Increment index for serial number generation
    ind += 1

print('done.')