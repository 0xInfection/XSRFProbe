import logging
import requests
from math import log

from xsrfprobe.files import discovered
from xsrfprobe.core.logger import VulnLogger, NovulLogger


def Entropy(req: requests.Response, form: str) -> None:
    """
    Evaluate the strength of CSRF tokens based on length and Shannon Entropy.
    """
    logger = logging.getLogger("EntropyChecker")
    logger.info("Starting CSRF token analysis...")

    weak_token = False
    # The minimum length of a csrf token should be 6 bytes.
    min_length = 6
    # I have never seen a CSRF token longer than 256 bytes,
    # so the main concept here is doubling that and checking
    # to make sure we don't check parameters which are
    # files in multipart uploads or stuff like that.
    #
    # Multipart uploads usually have a trailing sequence of
    # characters which could be misunderstood as a CSRF token.
    # This is a very important step with respect to
    # decreasing [[ False Positives ]].
    max_length = 512
    # Shannon Entropy calculated for a particular CSRF token
    # should be at least 2.4. If the token entropy is less
    # than that, the application request can be easily
    # forged making the application vulnerable even in
    # presence of a CSRF token.
    min_entropy = 3.0
    logger.info("Analysing Anti-CSRF Token Strength.")

    for xsrftoken in discovered.ANTI_CSRF_TOKENS:
        token = xsrftoken.token
        logger.info(f"Testing Anti-CSRF Token: {token}")

        # Check token length
        if len(token) <= min_length:
            logger.warning("CSRF Token length is less than 6 bytes. Token can be guessed/bruteforced.")
            VulnLogger(req.url, "Very Short Anti-CSRF Token.", f"Token: {token}")
            weak_token = True
        elif len(token) >= max_length:
            logger.info("CSRF Token length is equal to / exceeds 256 bytes. Token is robust.")
            NovulLogger(req.url, f"Long Anti-CSRF tokens with Good Strength. Token: {token}")

        # Calculate entropy
        logger.info("Calculating Shannon Entropy...")
        entropy = calcEntropy(token)
        logger.info(f"Calculated entropy: {token}")

        if entropy >= min_entropy:
            logger.info("High entropy detected. Endpoint is likely not vulnerable to CSRF attacks.")
            NovulLogger(req.url, f"High Entropy Anti-CSRF Tokens. Token: {token}")
        else:
            logger.warning("Low entropy detected. Endpoint is likely vulnerable to CSRF attacks.")
            VulnLogger(req.url, "Low Entropy Anti-CSRF Tokens.", f"Token: {token}")
            weak_token = True

        if weak_token:
            logger.critical(f"No robust CSRF tokens found. The CSRF tokens can possibly be bruteforced. Token: {token}")
            discovered.WEAK_TOKENS.append(token)


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