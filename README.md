# Password-Strength-Analyzer
import re
import hashlib
import getpass


# Common weak passwords
COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678",
    "qwerty", "abc123", "admin", "welcome",
    "letmein", "iloveyou"
}


def analyze_password(password):
    score = 0
    feedback = []

    # 1. Password Length
    length = len(password)

    if length >= 12:
        score += 3
    elif length >= 8:
        score += 2
        feedback.append("Use at least 12 characters for better security.")
    else:
        score += 0
        feedback.append("Password is too short. Use at least 8-12 characters.")

    # 2. Uppercase letters
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters (A-Z).")

    # 3. Lowercase letters
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters (a-z).")

    # 4. Numbers
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers (0-9).")

    # 5. Special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters like @, #, $, !.")

    # 6. Check common passwords
    if password.lower() in COMMON_PASSWORDS:
        score -= 3
        feedback.append("This is a commonly used password. Choose something unique.")

    # 7. Check repeated characters
    if re.search(r"(.)\1\1", password):
        score -= 1
        feedback.append("Avoid repeating the same character multiple times.")

    # Determine strength
    if score <= 2:
        strength = "WEAK"
    elif score <= 5:
        strength = "MEDIUM"
    elif score <= 7:
        strength = "STRONG"
    else:
        strength = "VERY STRONG"

    return score, strength, feedback


def generate_suggestion(password):
    """
    Gives a safer improvement suggestion without displaying
    or storing the original password.
    """

    suggestions = [
        "Use a longer password or passphrase (12+ characters).",
        "Mix uppercase and lowercase letters.",
        "Include numbers and special characters.",
        "Avoid names, birthdays, and common words.",
        "Use a unique password for every account."
    ]

    return suggestions


def create_password_hash(password):
    """
    Demonstrates basic cryptography using SHA-256.
    In real applications, use a password hashing algorithm
    such as Argon2 or bcrypt for storing passwords.
    """
    return hashlib.sha256(password.encode()).hexdigest()


def main():
    print("=" * 45)
    print("        PASSWORD STRENGTH ANALYZER")
    print("=" * 45)

    # getpass hides password while typing
    password = getpass.getpass("Enter your password: ")

    score, strength, feedback = analyze_password(password)

    print("\n" + "=" * 45)
    print("PASSWORD ANALYSIS RESULT")
    print("=" * 45)

    print(f"Password Length: {len(password)} characters")
    print(f"Strength Score: {score}/8")
    print(f"Password Strength: {strength}")

    # Display feedback
    if feedback:
        print("\nSuggestions:")
        for item in feedback:
            print(f"• {item}")
    else:
        print("\nExcellent! Your password meets all security checks.")

    print("\nGeneral Security Tips:")
    for suggestion in generate_suggestion(password):
        print(f"• {suggestion}")

    # Basic cryptography demonstration
    password_hash = create_password_hash(password)

    print("\nCryptography Demonstration:")
    print("Your password can be converted into a SHA-256 hash.")
    print("Password Hash:", password_hash)

    print("\n⚠ Important: Never store real passwords as plain text.")
    print("Use secure password hashing methods in real applications.")


if __name__ == "__main__":
    main()
