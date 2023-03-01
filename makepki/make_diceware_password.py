import os
import re
import secrets
import argparse

this_dir = os.path.dirname(os.path.realpath(__file__))

default_wordlist = os.path.abspath(os.path.join(this_dir, 'diceware.wordlist.asc'))


def read_wordlist(wordlist_file):
    """Read wordlist file. Only looks at lines that start with 5 integers from 1-6
    Assumes the wordlist has entries for 11111 - 66666, building a dict of the {dice rolls: word} pairs
    Note: a list with entries 0-55555 would be faster, but it doesn't make a big enough difference here"""
    word_regex = re.compile(r'^[1-6]{5}\s+')
    words = {}
    with open(wordlist_file, 'r') as f:
        for line in f:
            if word_regex.match(line):
                parts = line.strip().split()
                words[parts[0]] = parts[1]

    return words


def roll_dice(n):
    """Roll n 6-sided dice"""
    return [secrets.choice([1, 2, 3, 4, 5, 6]) for _ in range(n)]


def gen_password(n, wordlist_file):
    # Read wordlist
    words = read_wordlist(wordlist_file)

    # Generate password
    password = []
    for i in range(n):
        # Roll 5 dice
        dice = roll_dice(5)
        dice_str = ''.join(str(x) for x in dice)
        password.append(words[dice_str])

    return ' '.join(password)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate diceware password')
    parser.add_argument('n', type=int, help='Number of words in password')
    parser.add_argument('-w', '--wordlist', help='Wordlist file', default=default_wordlist)
    args = parser.parse_args()

    password = gen_password(args.n, args.wordlist)

    print(password)
