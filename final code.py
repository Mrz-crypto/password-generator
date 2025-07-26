import string
import random
import pyperclip

def generate_password():
    try:
        length = int(input("How many characters do you want in your password? "))

        if length < 8:
            print(" Password must be at least 8 characters long.")
            return

        chars = {
            'lower': list(string.ascii_lowercase),
            'upper': list(string.ascii_uppercase),
            'digit': list(string.digits),
            'punct': list(string.punctuation)
        }

        part1 = round(length * 0.3)
        part2 = round(length * 0.2)

        password_chars = random.sample(chars['lower'], part1) + \
                         random.sample(chars['upper'], part1) + \
                         random.sample(chars['digit'], part2) + \
                         random.sample(chars['punct'], part2)

        while len(password_chars) < length:
            password_chars.append(random.choice(string.ascii_letters + string.digits + string.punctuation))

        random.shuffle(password_chars)
        password = ''.join(password_chars)

        print(f"\n Generated Password: {password}")
        pyperclip.copy(password)
        print("Password copied to clipboard.")

    except ValueError:
        print("Invalid input! Please enter a number.")

generate_password()
