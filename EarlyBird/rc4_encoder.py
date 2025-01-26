import sys
import os

def rc4(data, key):
    keylen = len(key)
    s = list(range(256))
    j = 0

    for i in range(256):
        j = (j + s[i] + key[i % keylen]) % 256
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    encrypted = bytearray()

    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        encrypted.append(data[n] ^ s[(s[i] + s[j]) % 256])

    return encrypted

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./rc4.py <key> <filename>")
        exit(0)

    key = sys.argv[1]
    filename = sys.argv[2]

    with open(filename, 'rb') as f:
        data = f.read()

    encrypted = rc4(data, key.encode())

    encrypted_filename = f"{filename}.enc"
    with open(encrypted_filename, 'wb') as f:
        f.write(encrypted)

    print(f"Written {encrypted_filename}")

    # Rename the encrypted file to "buf"
    os.rename(encrypted_filename, "buf")

    # Convert "buf" to C array format using xxd
    os.system("xxd -i buf > shellcode.c")

    print("Converted buf to shellcode.c")
