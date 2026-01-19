import hashlib
import math
import secrets
import string
import uuid
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)
CORS(app)

# Load common passwords
COMMON_PASSWORDS = set()
try:
    with open('data/common_passwords.txt', 'r') as f:
        COMMON_PASSWORDS = set(line.strip().lower() for line in f)
except FileNotFoundError:
    pass

def calculate_entropy(password):
    if not password:
        return 0
    
    # Calculate Shannon Entropy
    char_count = {}
    for char in password:
        char_count[char] = char_count.get(char, 0) + 1
    
    entropy = 0
    for count in char_count.values():
        p = count / len(password)
        entropy -= p * math.log2(p)
    
    # Scale it to a 0-100 range roughly based on length and character set
    # A standard strong password has 4 bits per char approx.
    # We'll use a mix of Shannon and length-based scoring
    pool_size = 0
    if any(c in string.ascii_lowercase for c in password): pool_size += 26
    if any(c in string.ascii_uppercase for c in password): pool_size += 26
    if any(c in string.digits for c in password): pool_size += 10
    if any(c in string.punctuation for c in password): pool_size += 32
    
    if pool_size == 0: return 0
    
    potential_entropy = len(password) * math.log2(pool_size)
    # Balanced score: 50% length/pool, 50% randomness (shannon)
    final_score = (potential_entropy * 0.5) + (entropy * len(password) * 0.5)
    return min(100, int(final_score))

def analyze_hash_pattern(password):
    """
    Unique Concept: Salt + Hash pattern analysis.
    We look for repeating sequences or hex transitions in the SHA-256 result.
    """
    salt = uuid.uuid4().hex
    hasher = hashlib.sha256()
    hasher.update((salt + password).encode('utf-8'))
    hash_result = hasher.hexdigest()
    
    # Count unique hex characters in hash
    unique_hex = len(set(hash_result))
    # A random hash should have ~16 unique characters. 
    # If it has fewer, it's statistically slightly "patterned" (though unlikely for SHA-256)
    pattern_score = (unique_hex / 16) * 100
    return int(pattern_score), hash_result, salt

def generate_suggestions(password):
    suggestions = []
    
    # 1. Cryptographically secure random password
    secure_pass = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16))
    suggestions.append(secure_pass)
    
    # 2. Diceware-inspired passphrase
    words = ["Iron", "Safe", "Wall", "Cyber", "Logic", "Alpha", "Pulse", "Vault", "Cloud", "Ghost"]
    passphrase = '-'.join(secrets.choice(words) for _ in range(3)) + '-' + str(secrets.randbelow(999))
    suggestions.append(passphrase)
    
    # 3. Pattern-based upgrade
    upgraded = password
    if not any(c in string.ascii_uppercase for c in upgraded):
        upgraded += secrets.choice(string.ascii_uppercase)
    if not any(c in string.digits for c in upgraded):
        upgraded += secrets.choice(string.digits)
    if not any(c in string.punctuation for c in upgraded):
        upgraded += secrets.choice(string.punctuation)
    while len(upgraded) < 12:
        upgraded += secrets.choice(string.ascii_letters)
    suggestions.append(upgraded)
    
    return list(set(suggestions))[:3]

def detect_keyboard_patterns(password):
    patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'password']
    password_lower = password.lower()
    for p in patterns:
        if p in password_lower:
            return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    gen_type = data.get('type', 'Strong')
    
    length = 12
    chars = string.ascii_letters
    
    if gen_type == 'Simple':
        length = 8
        chars = string.ascii_lowercase + string.digits
    elif gen_type == 'Moderate':
        length = 10
        chars = string.ascii_letters + string.digits
    elif gen_type == 'Strong':
        length = 14
        chars = string.ascii_letters + string.digits + string.punctuation
    elif gen_type == 'Very Strong':
        length = 24
        chars = string.ascii_letters + string.digits + string.punctuation + " "
    
    # Ensure at least one of each required type for Strong/Very Strong
    password = []
    if gen_type in ['Strong', 'Very Strong']:
        password.append(secrets.choice(string.ascii_uppercase))
        password.append(secrets.choice(string.ascii_lowercase))
        password.append(secrets.choice(string.digits))
        password.append(secrets.choice(string.punctuation))
        remaining = length - 4
    else:
        remaining = length
        
    for _ in range(remaining):
        password.append(secrets.choice(chars))
        
    # Shuffle for randomness
    secrets.SystemRandom().shuffle(password)
    result = "".join(password).strip()
    
    return jsonify({'password': result})

@app.route('/analyze', methods=['POST'])
def analyze():
    # Rate limiting simulation
    if 'attempts' not in session:
        session['attempts'] = 0
    
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
        
    session['attempts'] += 1
    if session['attempts'] > 100: 
        return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429

    # 1. Dictionary Check
    is_common = password.lower() in COMMON_PASSWORDS
    
    # 2. Pattern Check
    has_kb_pattern = detect_keyboard_patterns(password)
    
    # 3. Entropy & Scoring
    entropy_score = calculate_entropy(password)
    
    # 4. Hash Analysis (Keep logic, hide details from response)
    hash_pattern_score, _, _ = analyze_hash_pattern(password)
    
    # Weighting the final score
    final_score = entropy_score
    if is_common: final_score = min(final_score, 10)
    if has_kb_pattern: final_score = min(final_score, 30)
    
    status = "Weak"
    if 41 <= final_score <= 70:
        status = "Medium"
    elif final_score > 70:
        status = "Strong"
    
    # 5. Suggestions
    suggestions = []
    if status != "Strong":
        suggestions = generate_suggestions(password)

    return jsonify({
        'score': int(final_score),
        'status': status,
        'entropy': round(entropy_score, 2),
        'hash_pattern_score': hash_pattern_score,
        'suggestions': suggestions,
        'is_common': is_common,
        'has_kb_pattern': has_kb_pattern,
        'checks': {
            'length': len(password) >= 8,
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'number': any(c.isdigit() for c in password),
            'special': any(c in string.punctuation for c in password)
        }
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
