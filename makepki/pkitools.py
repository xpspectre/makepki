# Helper functions
import re
import itertools


def expand(s):
    """Expand string into list of strings according to templating rules.
    [aa-bb] : range from integers aa to bb, inclusive, padding with 0's to maintain the same length
    [a-bb] : range from integers a to bb, inclusive, not padding with 0's
    [a|b|c] : alternative with string a or b or c"""

    matches = re.findall(r'\[(.+?)\]', s)  # lazy match for keep contents in separate brackets separate
    expansions = []
    for match in matches:

        if '-' in match:  # range
            expansion = []
            endpoints = match.split('-')
            assert len(endpoints) == 2, "A range can only have a start and an end"
            start = endpoints[0]
            end = endpoints[1]
            startVal = int(start)
            endVal = int(end)
            startLen = len(start)
            endLen = len(end)
            for i in range(startVal, endVal + 1):
                if startLen == endLen:  # pad with zeros (no additional effect unless vals, esp the start val, have explicit extra padding)
                    expansion.append(str(i).zfill(startLen))
                else:  # don't pad
                    expansion.append(str(i))

        elif '|' in match:  # alternation
            expansion = match.split('|')

        else:
            raise Exception('Illegal character in expansion')

        expansions.append(expansion)

    # Assemble combinations
    combos = itertools.product(*expansions)
    expandeds = []
    for entries in combos:
        expanded = s
        for entry in entries:
            expanded = re.sub(r'(\[.+?\])', entry, expanded, 1)
        expandeds.append(expanded)

    return expandeds
