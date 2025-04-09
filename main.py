
def read_file(file_name: str) -> bytes:
    """
    Function for getting byte-data from the specified file
    """
    with open(file_name, "rb") as f:
        result = f.read()
    return result


def find_repeating_key_length(key_stream: bytes, max_len: int = 1024):
    """
    Try to find the smallest repeating pattern in the key_stream.
    """

    for length in range(1, max_len + 1):
        segment = key_stream[:length]
        match = True
        for i in range(length, len(key_stream)):
            if key_stream[i] != segment[i % length]:
                match = False
                break
        if match:
            return length, segment
    return None, None


def xor_decrypt_partial(data: bytes, key: bytes, limit: int = 1024) -> bytes:
    """
    XOR's only the 'limit' amount of bytes in data
    """
    key_len = len(key)
    decrypted = bytearray()

    # Decrypt only first `limit` bytes
    for i in range(min(limit, len(data))):
        decrypted.append(data[i] ^ key[i % key_len])

    # Append the rest unchanged
    if len(data) > limit:
        decrypted += data[limit:]

    return bytes(decrypted)


def main():
    """
    Main function.

    Loads both 1111.jpg, 1111.jpg.crypted, 2222.jpg.crypted. Gets the key by XOR-ing the hex of original 1111.jpg, and
    it's crypted version. Using the resulting key, decrypts the crypted version of 1111.jpg, saves it in the
    1111_decrypted.jpg file. Uses the same key to decrypt the 2222.jpg.crypted, saves the resulting data in the
    2222_decrypted.jpg.

    """
    # Loading the byte-data from files
    original_1111 = read_file("1111.jpg")
    crypted_1111 = read_file("1111.jpg.crypted")
    crypted_2222 = read_file("2222.jpg.crypted")

    # ------------------------------------------ GETTING THE FULL KEY --------------------------------------------------
    similarity_count = 0   # variable to hold the amount of bytes that are the same in both encrypted and original files
    key = bytearray()

    for o, c in zip(original_1111, crypted_1111):
        xor = o ^ c
        if xor == 0x0:
            similarity_count += 1
        else:
            similarity_count = 0
        key.append(xor)
        # Check is more than 10k bytes are similar, if yes - stop the loop, and remove those the last 10k bytes from key
        if similarity_count >= 1000:
            key = key[:-1000]
            print(f"More than 10000 bytes are similar, breaking")
            break

    # Printing the whole key in the readable form
    print(f"full key is {(" ".join([key.hex()[i:i+2] for i in range (0, len(key.hex()), 2)]))}")
    key_length, repeating_key = find_repeating_key_length(key)  # Getting the smallest repeating key
    count = key.hex().count(repeating_key.hex())    # counting the smallest key occurrences

    # Formatting key in the readable form
    readable_key = " ".join([repeating_key.hex()[i:i+2] for i in range (0, len(repeating_key.hex()), 2)])
    print(f"resulting repeating key has a length of {key_length}, repeated {count} times in the full key, and has a value of: {readable_key}")
    print(f"byte length = {len(readable_key.split(" "))}")  # printing length of the key

    # --------------------------------------- DECRYPTING 1111.jpg.crypted ----------------------------------------------
    # Clear the file before writing data inside
    with open("1111_decrypted.jpg", "wb") as f:
        f.write(b"")

    # Get decrypted byte-data of the file
    decrypted_data = xor_decrypt_partial(crypted_1111, key)
    if original_1111 == decrypted_data:     # Double-check to make sure the resulting data matches the hex of 1111.jpg
        print("Hex values are the same")

    # Write byte-data in the file
    with open("1111_decrypted.jpg", "wb") as f:
        f.write(decrypted_data)

    # --------------------------------------- DECRYPTING 2222.jpg.crypted ----------------------------------------------
    # Clear the file before writing data inside
    with open("2222_decrypted.jpg", "wb") as f:
        f.write(b"")

    # Get decrypted byte-data of the file
    decrypted_data = xor_decrypt_partial(crypted_2222, key)

    # Write byte-data in the file
    with open("2222_decrypted.jpg", "wb") as f:
        f.write(decrypted_data)


# Script entry point
if __name__ == "__main__":
    main()
