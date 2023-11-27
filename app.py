from Crypto.Hash import SHA256
import random
from flask import Flask, render_template, request, session, redirect, url_for
from ast import literal_eval
from flask_session import Session

app = Flask(__name__, template_folder='Templates',static_folder='static')
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
DEFAULT_BLOCK_SIZE_1024 = 128 #the default block size that will be taken to encrypt the message when the key is 1024 bits long is 128 bytes
BYTE_SIZE_1024 = 128 #the default block size that will be taken to encrypt the message when the key is 1024 bits long is 128 bytes

DEFAULT_BLOCK_SIZE_2048 = 256  #the default block size that will be taken to encrypt the message when the key is 2048 bits long is 256 bytes
BYTE_SIZE_2048 = 256 #the default block size that will be taken to encrypt the message when the key is 2048 bits long is 256 bytes

DEFAULT_BLOCK_SIZE = DEFAULT_BLOCK_SIZE_1024 
BYTE_SIZE = BYTE_SIZE_1024

hash_algorithm = "SHA-256"  # will be used by default

def miller_rabin(n, k=10): # we will run miller rabin test 10 times to check get the chance of knowing if the number is prime or not. The probability of error is 1-1/4^10=0.9999990463
    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def primality_test(n): # we know that any composite can be written as a product of prime numbers. So, if we check if the number is divisible by any prime number less than it, we can know if it is prime or not
    if n < 2:
        return False
    low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
                  67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
                  149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
                  229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
                  313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401,
                  409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
                  499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
                  601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683,
                  691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
                  809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887,
                  907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if n in low_primes:
        return True
    for prime in low_primes:
        if n % prime == 0:
            return False 
    return miller_rabin(n) 

def generate_large_prime(keysize): # it generates a random number based on the user's keysize (1024 or 2048) and checks if it is prime or not
    while True:
        num = random.randrange(2 ** (keysize - 1), 2 ** keysize)
        if primality_test(num):
            return num

def key_generated(keysize): # it generates the public and private keys where (n,`e) is the public key and (n, d) is the private key)
    print("Generating prime p...")
    p = generate_large_prime(keysize)
    print("Generating prime q...")
    q = generate_large_prime(keysize)
    n = p * q
    m = (p - 1) * (q - 1)

    print("Generating e that is relatively prime to (p-1)*(q-1)...")
    while True:
        e = random.randrange(2 ** (keysize - 1), 2 ** keysize)
        if compute_gcd(e, m) == 1: # we check if e is relatively prime to (p-1)*(q-1)
            break

    print("Calculating d that is mod inverse of e...")
    d = find_mod_inverse(e, m)

    public_key = (n, e)

    return public_key, (n, d)

def compute_gcd(x, y): #returns the gcd of x and y
    while y:
        x, y = y, x % y
    return abs(x)

def find_mod_inverse(a, m):
    if compute_gcd(a, m) != 1: #we are using the tabulation methodto find the mod inverse of a and m
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def get_blocks_from_text(message, block_size=DEFAULT_BLOCK_SIZE):
    message_bytes = message.encode('ascii') # we encode the message to bytes using ascii encoding
    block_ints = [] 

    for block_start in range(0, len(message_bytes), block_size):
        block_int = 0
        for i in range(block_start, min(block_start + block_size, len(message_bytes))): 
            block_int += message_bytes[i] * (BYTE_SIZE ** (i % block_size)) # we convert the message to integer using the block size (128 or 256)
        block_ints.append(block_int)

    return block_ints
def get_text_from_blocks(block_ints, message_length, block_size=DEFAULT_BLOCK_SIZE):
    message = []

    for block_int in block_ints:
        block_message = []
        for i in range(block_size - 1, -1, -1):
            if len(message) + i < message_length:
                ascii_number = block_int >> (i * 7) & 0x7F #we right shift the block int by i*7 and then we do bitwise and with 0x7F to get the ascii number

                # Check if the calculated ASCII number is valid 
                if 0x20 <= ascii_number <= 0x7E:  # 0x20-0x7E are valid ASCII codes
                    block_message.insert(0, chr(ascii_number))
                else:
                    # Replace invalid bytes with ?
                    block_message.insert(0, '?')

        message.extend(block_message)

    return ''.join(message)


def custom_pow(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0: #we are using the square and multiply method to calculate the power
        if exponent % 2 == 1: #if the exponent is odd
            result = (result * base) % modulus #we multiply the result with base if the exponent is odd
        exponent = exponent // 2
        base = (base * base) % modulus #we square the base and take the modulus with the modulus value to get the remainder
    return result

def encrypt_message(message, public_key, block_size):
    encrypted_blocks = []

    # Extract public key components (n, e)
    n, e = public_key

    # Ensure that the message is a multiple of the block size
    padded_message = message.ljust((len(message) // block_size + 1) * block_size, '\0')

    for block in get_blocks_from_text(padded_message, block_size): #we get the blocks from the padded message and encrypt each block using the public key
        encrypted_block = custom_pow(block, e, n) #we encrypt the block using the public key
        encrypted_blocks.append(encrypted_block) 

    return encrypted_blocks, block_size


def decrypt_message(private_key, encrypted_blocks, message_length, block_size):
    decrypted_blocks = []

    n, d = private_key

    for encrypted_block in encrypted_blocks: #we decrypt the encrypted blocks using the private key and append it to the decrypted blocks
        decrypted_block = custom_pow(encrypted_block, d, n)
        decrypted_blocks.append(decrypted_block) #we decrypt the encrypted block using the private key

    return get_text_from_blocks(decrypted_blocks, message_length, block_size)


def generate_signature(message, private_key):
    # Extract private key components (n, d)
    n, d = private_key

    # Hash the message using SHA-256
    hashed_message = int(SHA256.new(message.encode()).hexdigest(), 16)

    # Sign the hashed message using the private key
    signature = custom_pow(hashed_message, d, n)

    return signature

def verify_signature(message, public_key, signature):
    # Extract public key components (n, e)
    n, e = public_key

    # Hash the message using SHA-256
    hashed_message = int(SHA256.new(message.encode()).hexdigest(), 16)

    # Verify the signature using the public key
    decrypted_signature = custom_pow(signature, e, n)
    return decrypted_signature == hashed_message

def generate_key(keysize):
    print(f"Generating key of size {keysize} bits...")
    public_key, private_key = key_generated(keysize)

    # Determine block size based on key size
    block_size = DEFAULT_BLOCK_SIZE_2048 if keysize == 2048 else DEFAULT_BLOCK_SIZE_1024

    return public_key, private_key, block_size

# def generate_random_message(length):
#     import random
#     import string
#     return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
# def test_encryption_decryption():
#     success_count = 0
#     iterations = 100

#     for i in range(iterations):
#         # Generate a key pair
#         keysize = 2048
#         public_key, private_key = key_generated(keysize)

#         # Generate a random message
#         random_message_length = 60
#         random_message = generate_random_message(random_message_length)

#         # Encrypt the message
#         encrypted_blocks, block_size = encrypt_message(random_message, public_key, DEFAULT_BLOCK_SIZE_2048)
#         generate_signature(random_message, private_key)
#         print(verify_signature(random_message, public_key, generate_signature(random_message, private_key)))
#         # Decrypt the message
#         decrypted_message = decrypt_message(private_key, encrypted_blocks, len(random_message), block_size)

#         # Check if original and decrypted messages match
#         if random_message == decrypted_message:
#             success_count += 1
#         print("this is 2048 bits")

#     # Print results
#     print(f"Number of successful matches: {success_count}/{iterations}")

# # Run the test
# test_encryption_decryption()




@app.route('/')
def home():
    return render_template('home.html')

@app.route('/generate', methods=['POST'])
def generate():
    keysize = request.form.get('keysize')

    if keysize not in ['1024', '2048']:
        return render_template('error.html', message='Invalid key size')

    try:
        keysize = int(keysize)
        public_key, private_key, block_size = generate_key(keysize)

        # Generate signature during key generation
        # message_for_signature = "Hello"
        # signature1 = generate_signature(message_for_signature, private_key)
        
        # # Verify the generated signature
        # is_signature_valid = verify_signature(message_for_signature, public_key, signature1)

        # Store public and private keys, block size, key size, and signature in the session
        session['public_key_n'] = str(public_key[0])
        session['public_key_e'] = str(public_key[1])
        session['private_key_d'] = str(private_key[1])
        session['private_key_n'] = str(private_key[0])
        session['block_size'] = block_size
        session['keysize'] = keysize

        return render_template('generate.html', keysize=keysize, public_key=public_key,
                               private_key_d=str(private_key[1]), private_key_n=str(private_key[0]))
    except Exception as e:
        print(f"Error generating key: {e}")
        return render_template('error.html', message='Error generating key')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    keysize = int(request.form.get('keysize'))
    print(f"Received keysize: {keysize}")

    # Convert public key components to integers
    public_key_n = int(request.form.get('public_key_n'))
    public_key_e = int(request.form.get('public_key_e'))
    public_key = (public_key_n, public_key_e)
    print(f"Received public key: {public_key}")

    message = request.form.get('message')
    print(f"Received message: {message}")

    try:
        # Retrieve block size and signature from the session
        block_size = int(session.get('block_size', DEFAULT_BLOCK_SIZE_2048))
        signature = session.get('signature')

        encrypted_blocks, _ = encrypt_message(message, public_key, block_size)
        encrypted_message = ' '.join(map(str, encrypted_blocks))
        print(f"Encrypted message: {encrypted_message}")

        # Verify the signature
        is_signature_valid = verify_signature(message, public_key, signature)

        return render_template('result.html', keysize=keysize, operation='Encrypt',
                               message=message, result=encrypted_message, original_length=len(message),
                               is_signature_valid=is_signature_valid)
    except Exception as e:
        print(f"Error during encryption: {e}")
        return render_template('error.html', message='Error during encryption')


@app.route('/decrypt', methods=['POST'])
def decrypt():
    keysize_str = session.get('keysize')

    if not keysize_str:
        return render_template('error.html', message='Key size not found in session')

    try:
        keysize = int(keysize_str)

        private_key_n = session.get('private_key_n')
        private_key_d = session.get('private_key_d')

        if private_key_n is None or private_key_d is None:
            return render_template('error.html', message='Private keys not found in session')

        private_key = (int(private_key_n), int(private_key_d))

        encrypted_message = request.form.get('encrypted_message')
        encrypted_blocks = list(map(int, encrypted_message.split()))
        original_message_length = int(request.form.get('original_length'))

        if not encrypted_blocks:
            raise ValueError("Encrypted blocks are empty")

        # Retrieve block size from the session
        block_size = int(session.get('block_size', DEFAULT_BLOCK_SIZE_2048))

        decrypted_message = decrypt_message(private_key, encrypted_blocks, original_message_length, block_size)

        if decrypted_message is None:
            raise ValueError("Error during decryption")

        return render_template('results.html', keysize=keysize, operation='Decrypt',
                               message=encrypted_message, result=decrypted_message, private_key=private_key)
    except ValueError as e:
        print(f"Error during decryption: {e}")
        return render_template('error.html', message=str(e))
    except Exception as e:
        print(f"Unexpected error during decryption: {e}")
        return render_template('error.html', message=f'Unexpected error during decryption: {str(e)}')



@app.route('/private-keys')
def private_keys():
    private_key_d = session.get('private_key_d', None)
    private_key_n = session.get('private_key_n', None)

    if private_key_d is None or private_key_n is None:
        return render_template('error.html', message='Private keys not found')

    return render_template('private_keys.html', private_key_d=private_key_d, private_key_n=private_key_n)

@app.route('/return-home', methods=['POST'])
def return_home():
    keep_keys = 'keep_keys' in request.form

    if keep_keys:
        # Redirect the user to the 'generate' page
        return redirect(url_for('generate'))
    else:
        # Delete specific keys from the session
        session.pop('private_key_d', None)
        session.pop('private_key_n', None)

    return redirect(url_for('home'))

@app.route('/private-keys', endpoint='view_private_keys')
def private_keys():
    private_key_d = session.get('private_key_d', None)
    private_key_n = session.get('private_key_n', None)

    if private_key_d is None or private_key_n is None:
        return render_template('error.html', message='Private keys not found')

    return render_template('private_keys.html', private_key_d=private_key_d, private_key_n=private_key_n)
@app.route('/continue', methods=['POST'])
def continue_encrypt():
    try:
        keysize_str = session.get('keysize')
        if not keysize_str:
            raise ValueError("Key size not found in session")

        keysize = int(keysize_str)

        public_key_n = session.get('public_key_n')
        public_key_e = session.get('public_key_e')

        if public_key_n is None or public_key_e is None:
            raise ValueError("Public keys not found in session")

        public_key = (int(public_key_n), int(public_key_e))

        # Retrieve block size from the session
        block_size = int(session.get('block_size', DEFAULT_BLOCK_SIZE_2048))

        # Redirect the user to the page where they can enter a new message
        return render_template('continue.html', keysize=keysize, public_key=public_key, block_size=block_size)

    except ValueError as e:
        print(f"Error during continuing: {e}")
        return render_template('error.html', message=str(e))
    except Exception as e:
        print(f"Unexpected error during continuing: {e}")
        return render_template('error.html', message=f'Unexpected error during continuing: {str(e)}')



if __name__ == '__main__':
    app.run(debug=True)
