from unittest import TestCase

from makepki.make_diceware_password import gen_password, default_wordlist


class DicewareTest(TestCase):
    def test_gen_password(self):
        for i in range(1, 11):
            password = gen_password(i, default_wordlist)
            self.assertEqual(i, len(password.split()))
