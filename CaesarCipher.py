def remove_foreign_chars(text: str) -> str:
    """Removes characters other than letters, digits, and spaces."""
    import re
    # Use a regular expression to replace all characters that are not
    # letters (a-z, A-Z), digits (0-9), or spaces with an empty string.
    return re.sub(r'[^a-zA-Z0-9 ]', '', text)


def caesar_cipher(
        mode: str,  # Either 'encode' or 'decode'
        text: str,
        shift: int,
        mod: int,
        charset: str,
        foreign_chars: str
) -> str:
    """
    Applies the Caesar Cipher (encryption or decryption) to the input text.
    :param mode: 'encode' or 'decode'
    :param text: The text to process
    :param shift: The shift amount
    :param mod: The modulus (used for wrap-around)
    :param charset: The alphabet or character set used for encryption
    :param foreign_chars: '1' to remove non-alphanumeric characters
    :return: The encoded or decoded text
    """

    # If mode is 'decode', reverse the direction of the shift
    if mode == "decode":
        shift = -shift

    # If foreign_chars == '1', remove characters not in the alphabet
    if foreign_chars == "1":
        text = remove_foreign_chars(text)

    # Convert the charset to lowercase for consistency
    charset = charset.lower()
    result = ""

    # Iterate over each character in the input text
    for char in text:
        lower_char = char.lower()

        # If the character exists in the charset, apply the shift
        if lower_char in charset:
            index = charset.index(lower_char)
            new_index = (index + shift) % mod  # Apply shift with modulo

            # Handle negative indices (wrap around)
            if new_index < 0:
                new_index += mod

            # Get the new shifted character
            new_char = charset[new_index]

            # Preserve uppercase letters if the original was uppercase
            if char.isupper():
                new_char = new_char.upper()

            result += new_char
        else:
            # If character not in charset, leave it unchanged
            result += char

    return result


# --- Example usage (simulating what the original HTML/JS form did) ---

if __name__ == "__main__":
    print("=== Caesar Cipher (Python Version) ===")

    # Get user inputs for encryption/decryption parameters
    mode = input("Choose mode [encode/decode]: ").strip().lower()
    text = input("Enter text: ")
    shift = int(input("Enter shift value (e.g., 3): "))
    mod = int(input("Enter modulo value (e.g., 26): "))
    charset = input("Enter alphabet (e.g., abcdefghijklmnopqrstuvwxyz): ")
    letter_case = input("Letter case? [1=keep, 2=lower, 3=upper]: ")
    foreign_chars = input("Remove non-alphanumeric characters? [1=yes, 0=no]: ")

    # Run Caesar cipher with the provided parameters
    output = caesar_cipher(mode, text, shift, mod, charset, foreign_chars)

    # Adjust final text casing if requested
    if letter_case == "2":
        output = output.lower()
    elif letter_case == "3":
        output = output.upper()

    # Display the final result
    print("\nResult:", output)
