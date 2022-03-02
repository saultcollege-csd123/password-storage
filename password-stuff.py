import hashlib
import os

password = input("What is the password? ")


algo = 'sha256'
salt = os.urandom(20)
iterations = 500000
hash = hashlib.pbkdf2_hmac(algo, password.encode(), salt, iterations)

# Store the hash AND the config for generating the hash (so that we can reuse that config later)
password_hash= f"{algo}${iterations}${salt.hex()}${hash.hex()}"

print(password_hash)

with open("pw.txt", "w") as f:
    f.write(password_hash)

while True:

    password_to_check = input("Enter a password to try: ")

    with open("pw.txt") as f:
        password_hash = f.readline()

    # Restore the config that was used to generate this hash (see comment above)
    (algo, iterations, salt, hash) = password_hash.split("$")

    # Compare the stored hash with the new hash generated using the same config as the stored hash
    if bytes.fromhex(hash) == hashlib.pbkdf2_hmac(algo, password_to_check.encode(), bytes.fromhex(salt), int(iterations)):
        print("Yay, you entered the right password!")
    else:
        print("Nope")