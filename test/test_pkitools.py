from unittest import TestCase

from makepki.pkitools import expand


class PkiToolsTest(TestCase):
    def test_expand_sequential(self):
        input = 'node[01-20]'
        outputs = expand(input)
        for i in range(0, 20):
            self.assertEqual(f'node{i + 1:02}', outputs[i])

    def test_expand_complex(self):
        input = 'abc[01-03]def[9-11]ghi[x|yy]'
        outputs = expand(input)
        self.assertEqual(18, len(outputs))
        self.assertEqual([
            'abc01def9ghix',
            'abc01def9ghiyy',
            'abc01def10ghix',
            'abc01def10ghiyy',
            'abc01def11ghix',
            'abc01def11ghiyy',
            'abc02def9ghix',
            'abc02def9ghiyy',
            'abc02def10ghix',
            'abc02def10ghiyy',
            'abc02def11ghix',
            'abc02def11ghiyy',
            'abc03def9ghix',
            'abc03def9ghiyy',
            'abc03def10ghix',
            'abc03def10ghiyy',
            'abc03def11ghix',
            'abc03def11ghiyy'
        ], outputs)
