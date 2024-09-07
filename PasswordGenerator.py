from flask import Flask, jsonify, render_template, request
import secrets
import string
import math
from collections import Counter

app = Flask(__name__)

# Minimum password length recommended for security
MIN_PASSWORD_LENGTH = 16

# List of common patterns to avoid (optional, can be expanded)
COMMON_WEAK_PATTERNS = [
    'password', '123456', 'qwerty', 'letmein', 'welcome', 'iloveyou',
    'admin', 'user', 'guest', 'abc123', 'pass', '000000'
]

def calculate_entropy(password_length, char_set_length):
    """Calculates the entropy of the password based on its length and the size of the character set."""
    entropy = password_length * math.log2(char_set_length)
    return entropy

def check_weak_patterns(password):
    """Checks if the generated password matches any common weak patterns."""
    for pattern in COMMON_WEAK_PATTERNS:
        if pattern in password.lower():
            return True
    return False

def check_repeating_characters(password):
    """Check if the password contains too many repeating characters."""
    counts = Counter(password)
    for count in counts.values():
        if count > (len(password) // 2):  # Arbitrary threshold: 50% repetition
            return True
    return False

def generate_password(length=MIN_PASSWORD_LENGTH, include_upper=True, include_lower=True, include_digits=True, include_special=True, avoid_similar=False):
    """Generates a random password with specified conditions and extra security checks."""
    
    if length < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password length must be at least {MIN_PASSWORD_LENGTH} characters for security.")
    
    char_set = ''
    
    if include_upper:
        char_set += string.ascii_uppercase
    if include_lower:
        char_set += string.ascii_lowercase
    if include_digits:
        char_set += string.digits
    if include_special:
        char_set += string.punctuation

    if avoid_similar:
        char_set = char_set.translate(str.maketrans('', '', 'O0lI1'))  # Remove visually similar characters

    if not char_set:
        raise ValueError("At least one character set must be selected")

    # Generate password using cryptographically secure random generator
    password = ''.join(secrets.choice(char_set) for _ in range(length))

    # Security checks to ensure no common weak patterns and minimal repetition
    if check_weak_patterns(password):
        raise ValueError("Generated password matches common weak patterns. Please regenerate.")
    
    if check_repeating_characters(password):
        raise ValueError("Generated password contains too many repeating characters. Please regenerate.")

    # Calculate entropy based on the actual size of the character set used
    entropy = calculate_entropy(length, len(char_set))

    return password, entropy

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-password', methods=['POST'])
def password_generator():
    try:
        data = request.json
        password, entropy = generate_password(
            length=data.get('length', MIN_PASSWORD_LENGTH),
            include_upper=data.get('include_upper', True),
            include_lower=data.get('include_lower', True),
            include_digits=data.get('include_digits', True),
            include_special=data.get('include_special', True),
            avoid_similar=data.get('avoid_similar', False)
        )
        return jsonify({
            'password': password,
            'entropy': f"{entropy:.2f} bits"
        }), 200
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400

if __name__ == "__main__":
    app.run(debug=True)
