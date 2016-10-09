import argparse
import re
from random import SystemRandom


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
    sys_random = SystemRandom()
    return [sys_random.randrange(1, 7) for i in range(n)]


if __name__ == "__main__":
    # Parse args
    parser = argparse.ArgumentParser(description='Generate diceware password')
    parser.add_argument('n', type=int, help='Number of words in password')
    parser.add_argument('-w', '--wordlist', help='Wordlist file', default='diceware.wordlist.asc')
    args = parser.parse_args()

    n = args.n
    wordlist_file = args.wordlist

    # Read wordlist
    words = read_wordlist(wordlist_file)

    # Generate password
    password = []
    for i in range(n):
        # Roll 5 dice
        dice = roll_dice(5)
        dice_str = ''.join(str(x) for x in dice)
        password.append(words[dice_str])

    print(' '.join(password))
