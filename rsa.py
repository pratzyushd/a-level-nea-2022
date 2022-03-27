import random
import math

FIRST_100_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
                    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
                    127, 131, 137, 139, 149, 151, 157, 163, 167,
                    173, 179, 181, 191, 193, 197, 199, 211, 223,
                    227, 229, 233, 239, 241, 251, 257, 263, 269,
                    271, 277, 281, 283, 293, 307, 311, 313, 317,
                    331, 337, 347, 349, 353, 359, 367, 373, 379,
                    383, 389, 397, 401, 409, 419, 421, 431, 433,
                    439, 443, 449, 457, 461, 463, 467, 479, 487,
                    491, 499, 503, 509, 521, 523, 541]


def generate_n_bit_random(n: int) -> int:
    """Generate a n bit long random number

    Args:
        n (int): number of bits

    Returns:
        int: decimal representation of n bit long random number
    """
    return random.randint(2**(n - 1) + 1, 2**(n) + 1)

def generate_initial_prime(n: int) -> int:
    """Check generated number against the list of the first 100 prime numbers

    Args:
        n (int): length of prime number in bits

    Returns:
        int: potential prime number candidate
    """
    complete = False
    while not complete:
        candidate = generate_n_bit_random(n)
        factor_found = False
        for prime in FIRST_100_PRIMES:
            if candidate % prime == 0 and prime**2 <= candidate:
                factor_found = True
                break
        if not factor_found:
            complete = True
    return candidate


def check_if_composite(base: int, even_component: int, pow_of_2: int,
                    candidate: int) -> bool:
    """Check if a number is composite using the Miller-Rabin test

    Args:
        base (int): the value a that is used as the base
        even_component (int): the odd multiple that makes 2^pow_of_2 =
                            candidate - 1
        pow_of_2 (int): the maximum power s
        candidate (int): the value of n

    Returns:
        bool: represents whether number is composite or not
    """
    # Check if a^q = 1 (mod n)
    # pow function documentation: pow(base, exponent, modulus)
    if pow(base, even_component, candidate) == 1:
        return False
    # Go through each value of i and see if a^(2^i * q) = -1 (mod n)
    for i in range(pow_of_2):
        # candidate - 1 = -1 (mod candidate)
        if pow(base, 2**i * even_component, candidate) == candidate - 1:
            return False
    # If passed all above tests, must be composite
    return True

def pass_miller_rabin(candidate: int) -> bool:
    """Parent function for the Miller-Rabin test

    Args:
        candidate (int): potential prime candidate

    Returns:
        bool: whether the candidate passed the primailty test 20 times
    """
    pow_of_2 = 0
    even_component = candidate - 1

    # Get the maximum power of 2, and the value that remains to multiply it by
    while even_component % 2 == 0:
        even_component = even_component // 2
        pow_of_2 += 1

    # Run the test for 20 trials
    num_trials = 20
    for i in range(num_trials):
        # Generate a new base every time
        base = random.randint(2, candidate-1)
        if check_if_composite(base, even_component, pow_of_2, candidate):
            return False
    return True

def get_prime() -> int:
    """Caller function for generating a prime

    Returns:
        int: prime number (or assumed to be after 20 passes with Miller-Rabin
        test)
    """
    found = False
    while not found:
        n = 1024
        candidate = generate_initial_prime(n)
        if not pass_miller_rabin(candidate):
            continue
        else:
            found = True
    return candidate

def encrypt_message(prime_1: int, prime_2: int, message: str) -> str:
    """Encrypting the message with RSA encryption given the primes and the
    message.

    Args:
        prime_1 (int): first prime number
        prime_2 (int): second prime number
        message (str): plaintext message

    Returns:
        str: encrypted message
    """
    modulus = prime_1 * prime_2
    # This value is hard coded usually, as in practice it is generally set to
    # this value for efficiency purposes.
    other_prime = 65537
    # Validation: don't allow empty message to be passed
    if len(message) < 1:
        return None
    # If the plaintext number becomes too big, truncate it
    elif len(message) > 100:
        message = message[0:100]
    message = message.upper()
    # Create a large integer representation of the number
    plaintext = "".join([str(ord(x)) for x in message])
    # Convert to an integer for mathematical operations
    plaintext = int(plaintext)
    ciphertext = pow(plaintext, other_prime, modulus)
    return str(ciphertext)

def decrypt_message(prime_1: int, prime_2: int, message: str) -> str:
    """Decrypt message with RSA encryption given the primes and the ciphertext.

    Args:
        prime_1 (int): first prime number
        prime_2 (int): second prime number
        message (str): ciphertext

    Returns:
        str: decrypted message
    """
    modulus = prime_1 * prime_2
    ciphertext = int(message)
    carm_tot = math.lcm(prime_1-1, prime_2-1)
    # As with encryption, the value for the other prime is generally hard coded
    # to this value as it is the most efficient
    other_prime = 65537
    # Create the private key using the modular inverse
    private_key = pow(other_prime, -1, carm_tot)
    plaintext = pow(ciphertext, private_key, modulus)
    plaintext = str(plaintext)
    message = [chr(int(plaintext[x:x+2])) for x in range(0,len(plaintext), 2)]
    return "".join(message)