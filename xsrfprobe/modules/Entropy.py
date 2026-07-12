from math import log


def calcEntropy(data: str):
    """
    Calculate Shannon Entropy of a given string.
    """
    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * log(p_x, 2)

    return entropy
