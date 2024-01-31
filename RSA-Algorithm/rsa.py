import random

def is_prime(n):
    """
    Check if a number is prime.
    :param n: Integer to check for primality.
    :return: True if prime, False otherwise.
    """
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_large_prime(size):
    """
    Generate a large prime number of given bit size.
    :param size: Bit size of the prime number.
    :return: A prime number.
    """
    while True:
        num = random.randrange(2**(size - 1), 2**size)
        if is_prime(num):
            return num

def find_gcd(a, b):
    """
    Find the greatest common divisor of two numbers.
    :param a: First number.
    :param b: Second number.
    :return: GCD of a and b.
    """
    while b != 0:
        a, b = b, a % b
    return a

def find_multiplicative_inverse(e, phi):
    """
    Find the multiplicative inverse of e modulo phi.
    :param e: Integer e (part of the public key).
    :param phi: Euler's totient of n.
    :return: The multiplicative inverse of e modulo phi.
    """
    return pow(e, -1, phi)

def generate_key(size):
    """
    Generate RSA public and private keys.
    :param size: Bit size of the keys.
    :return: Tuple of public and private keys.
    """
    p = generate_large_prime(size//2)
    q = generate_large_prime(size//2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = random.randint(1, phi)
    g = find_gcd(e, phi)
    while g != 1:
        e = random.randint(1, phi)
        g = find_gcd(e, phi)
        
    d = find_multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt_msg(key, plaintext):
    """
    Encrypt a plaintext message using RSA algorithm.
    :param key: Public key (e, n).
    :param plaintext: Message to be encrypted.
    :return: Encrypted message as a list of integers.
    """
    e, n = key
    return [pow(ord(char), e, n) for char in plaintext]

def decrypt_msg(key, ciphertext):
    """
    Decrypt a ciphertext message using RSA algorithm.
    :param key: Private key (d, n).
    :param ciphertext: Encrypted message as a list of integers.
    :return: Decrypted plaintext message.
    """
    d, n = key
    return ''.join(chr(pow(char, d, n)) for char in ciphertext)

def run_sender(receiver_s_public_key):
    print("\n[Sender]")
    message = input("Enter your message to send: ")
    encrypted_message = encrypt_msg(receiver_s_public_key, message)
    print("Sending encrypted message:", encrypted_message)
    return encrypted_message

def run_receiver(receiver_s_private_key, encrypted_message):
    print("\n[Receiver]")
    print("Received encrypted message:", encrypted_message)
    decrypted_message = decrypt_msg(receiver_s_private_key, encrypted_message)
    print("Decrypted message:", decrypted_message)
    
if __name__ == "__main__":
    print("RSA Encryption/Decryption")

    # Generating keys
    key_size = int(input("Enter key size in bits (e.g., 16, 32, 64): "))
    
    s_public_key, s_private_key = generate_key(key_size)
    r_public_key, r_private_key = generate_key(key_size)
    
    print(f"Public Key: {s_public_key}")
    print(f"Private Key: {s_private_key}")

    while True:
        print("\nChoose an option:")
        print("1. Standard RSA Encryption/Decryption")
        print("2. Digital Signature (Sign with Private Key)")
        print("3. Combined (Sign then Encrypt)")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            # Encrypt a Message and Decrypt
            message = input("[Sender] Enter a message to encrypt: ")
            encrypted_message = encrypt_msg(s_public_key, message)
            print("[Sender] Encrypted Message: ", encrypted_message)
            print("\n[Receiver] Decrypting the message...")
            decrypted_message = decrypt_msg(s_private_key, encrypted_message)
            print("[Receiver] Decrypted Message: ", decrypted_message)

        elif choice == '2':
            # Sign a Message and Verify
            message = input("[Sender] Enter a message to sign: ")
            signature = encrypt_msg(s_private_key, message)
            print("[Sender] Digital Signature: ", signature)
            print("\n[Receiver] Verifying the message...")
            verified_message = decrypt_msg(s_public_key, signature)
            print("[Receiver] Verified Message: ", verified_message)

        elif choice == '3':
            # Sign a Message, Encrypt and Decrypt
            message = input("[Sender] Enter a message to sign and encrypt: ")
            signed_message = encrypt_msg(s_private_key, message)
            signed_message_str = ','.join(map(str, signed_message)) # map will convert all integers into strings
            encrypted_signed_message = encrypt_msg(r_public_key, signed_message_str)
            print("[Sender] Encrypted Signed Message: ", encrypted_signed_message)

            print("\n[Receiver] Decrypting and verifying the message...")
            decrypted_signed_message_str = decrypt_msg(r_private_key, encrypted_signed_message)
            decrypted_signed_message = list(map(int, decrypted_signed_message_str.split(',')))
            original_message = decrypt_msg(s_public_key, decrypted_signed_message)
            print("[Receiver] Original Message: ", original_message)

        elif choice == '4':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice, please try again.")

        input("Press Enter to continue...")
