import os
import yaml
import socket
import tempfile
from unittest import TestCase

from makepki.make_pki import build

# Try building all the example configs
this_dir = os.path.dirname(os.path.realpath(__file__))
data_dir = os.path.join(this_dir, '../configs')


class MakePkiTest(TestCase):
    # TODO: actually load the certs and test them

    def test_build_example(self):
        config_file = os.path.join(data_dir, 'example.conf')
        with open(config_file, 'r') as f:
            doc = yaml.safe_load(f)

        with tempfile.TemporaryDirectory() as tempdir:
            build(doc, tempdir)

            output_dir = os.path.join(tempdir, 'example.com')
            self.assertTrue(os.path.exists(output_dir))

            self.assertTrue(os.path.exists(os.path.join(output_dir, 'ca.key')))
            self.assertTrue(os.path.exists(os.path.join(output_dir, 'ca.pem')))

            expected_nodes = ['node1', 'node2', socket.gethostname(), 'node03', 'node04', 'node05', '127.0.0.1']
            for node in expected_nodes:
                self.assertTrue(os.path.exists(os.path.join(output_dir, node + '.key')))
                self.assertTrue(os.path.exists(os.path.join(output_dir, node + '.pem')))

    def test_build_ips(self):
        config_file = os.path.join(data_dir, 'ips.conf')
        with open(config_file, 'r') as f:
            doc = yaml.safe_load(f)

        with tempfile.TemporaryDirectory() as tempdir:
            build(doc, tempdir)

            output_dir = os.path.join(tempdir, 'example.com')
            self.assertTrue(os.path.exists(output_dir))

            self.assertTrue(os.path.exists(os.path.join(output_dir, 'ca.key')))
            self.assertTrue(os.path.exists(os.path.join(output_dir, 'ca.pem')))

            expected_nodes = ['ips1', 'ips2']
            for node in expected_nodes:
                self.assertTrue(os.path.exists(os.path.join(output_dir, node + '.key')))
                self.assertTrue(os.path.exists(os.path.join(output_dir, node + '.pem')))
                self.assertTrue(os.path.exists(os.path.join(output_dir, node + '.p12')))

    def test_build_openvpn(self):
        config_file = os.path.join(data_dir, 'openvpn.conf')
        with open(config_file, 'r') as f:
            doc = yaml.safe_load(f)

        with tempfile.TemporaryDirectory() as tempdir:
            build(doc, tempdir)

            output_dir = os.path.join(tempdir, 'example.org')
            self.assertTrue(os.path.exists(output_dir))

            self.assertTrue(os.path.exists(os.path.join(output_dir, 'ca.key')))
            self.assertTrue(os.path.exists(os.path.join(output_dir, 'ca.pem')))

            expected_nodes = ['client1', 'client2', 'client3', 'server']
            # TODO: ensure server and client certs hae proper usage
            for node in expected_nodes:
                self.assertTrue(os.path.exists(os.path.join(output_dir, node + '.key')))
                self.assertTrue(os.path.exists(os.path.join(output_dir, node + '.pem')))
