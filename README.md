# Ken 盾 (Ken Shield) 🛡️

**Ken 盾** is a professional, high-performance Password Strength Analyzer and Generator suite. Built with Python Flask and a premium glassmorphic UI, it uses advanced cryptographic principles like Shannon Entropy and SHA-256 pattern analysis to provide real-time security insights.

## ✨ Key Features

- **Dynamic Strength Analysis**: Real-time scoring (0-100) with color-coded feedback (Weak, Medium, Strong).
- **Shannon Entropy Engine**: Measures the true randomness of your passwords in bits.
- **Privacy-First Hash Analysis**: Uses SHA-256 and unique salts to analyze patterns without exposing raw sensitive data.
- **Smart Password Generator**: 
  - Generates **Simple, Moderate, Strong, and Very Strong** options.
  - One-click copy with visual feedback.
  - Cryptographically secure randomness powered by the `secrets` module.
- **Common Password Check**: Integrated dictionary check against 10K+ leaked passwords.
- **Keyboard Pattern Detection**: Flags QWERTY sequences and predictable numeric runs.
- **Professional Aesthetics**: Premium dark-mode interface with dynamic background transitions based on security levels.

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- `pip` (Python package manager)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/ken-shun.git
   cd ken-shun
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the suite**:
   Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your modern web browser.

## 🛠️ Technology Stack
- **Backend**: Python (Flask)
- **Frontend**: HTML5, Vanilla CSS3 (Glassmorphism), JavaScript (ES6+)
- **Security**: SHA-256 Hashing, UUID Salting, Shannon Entropy Formula

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Disclaimer
Ken 盾 is a local security tool. For maximum safety, never share your master passwords with third-party web services. This tool is designed for entropy analysis and ethical security testing.

---
© 2024 **Ken 盾**. All Rights Reserved. Professional Security Suite.
