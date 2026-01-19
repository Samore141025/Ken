const passwordInput = document.getElementById('passwordInput');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');
const scoreText = document.getElementById('scoreText');
const suggestionsBox = document.getElementById('suggestionsBox');
const suggestionsList = document.getElementById('suggestionsList');
const entropyVal = document.getElementById('entropyVal');
const hashScore = document.getElementById('hashScore');
const toggleVisibility = document.getElementById('toggleVisibility');

// Generator elements
const genType = document.getElementById('genType');
const generateBtn = document.getElementById('generateBtn');
const genResult = document.getElementById('genResult');
const genPassText = document.getElementById('genPassText');
const copyGenBtn = document.getElementById('copyGenBtn');

const checkElements = {
    length: document.getElementById('chkLength'),
    uppercase: document.getElementById('chkUpper'),
    lowercase: document.getElementById('chkLower'),
    number: document.getElementById('chkNumber'),
    special: document.getElementById('chkSpecial'),
    dictionary: document.getElementById('chkDictionary')
};

let analysisTimeout;

passwordInput.addEventListener('input', () => {
    const password = passwordInput.value;

    // Quick local checks for immediate feedback
    updateLocalChecks(password);

    // Debounce the heavy backend analysis
    clearTimeout(analysisTimeout);
    if (password.length > 0) {
        analysisTimeout = setTimeout(() => {
            analyzePassword(password);
        }, 400);
    } else {
        resetUI();
    }
});

function updateLocalChecks(password) {
    const checks = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[^A-Za-z0-9]/.test(password)
    };

    for (const [key, isValid] of Object.entries(checks)) {
        if (checkElements[key]) {
            const icon = checkElements[key].querySelector('i');
            if (isValid) {
                checkElements[key].classList.add('valid');
                icon.className = 'fas fa-check-circle';
            } else {
                checkElements[key].classList.remove('valid');
                icon.className = 'fas fa-circle-notch';
            }
        }
    }
}

async function analyzePassword(password) {
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });

        const data = await response.json();

        if (response.status === 429) {
            strengthText.innerText = "Too Many Attempts";
            return;
        }

        // Update Score & Meter
        const score = data.score;
        strengthBar.style.width = `${score}%`;
        scoreText.innerText = `${score}/100`;

        // Color transition & Body Background
        let color = '#ef4444'; // Weak
        let bgClass = 'bg-weak';

        if (score >= 41 && score <= 70) {
            color = '#f59e0b'; // Medium
            bgClass = 'bg-medium';
        } else if (score > 70) {
            color = '#10b981'; // Strong
            bgClass = 'bg-strong';
        }

        document.body.className = bgClass;
        strengthBar.style.background = color;
        strengthText.innerText = data.status;
        strengthText.style.color = color;

        // Update Stats
        entropyVal.innerText = data.entropy;
        hashScore.innerText = `${data.hash_pattern_score}%`;
        // HASH DATA HIDDEN PER USER REQUEST

        // Dictionary Check UI
        const dictIcon = checkElements.dictionary.querySelector('i');
        if (!data.is_common && !data.has_kb_pattern) {
            checkElements.dictionary.classList.add('valid');
            dictIcon.className = 'fas fa-shield-alt';
            checkElements.dictionary.innerHTML = '<i class="fas fa-shield-alt"></i> Secure Pattern';
        } else {
            checkElements.dictionary.classList.remove('valid');
            dictIcon.className = 'fas fa-exclamation-triangle';
            checkElements.dictionary.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Common/Patterned';
        }

        // Suggestions
        if (data.suggestions && data.suggestions.length > 0) {
            suggestionsBox.style.display = 'block';
            suggestionsList.innerHTML = data.suggestions.map(s => `
                <div class="suggestion-item" onclick="copyToInput('${s}')">
                    <span>${s}</span>
                    <button class="copy-btn"><i class="fas fa-arrow-up"></i> Use</button>
                </div>
            `).join('');
        } else {
            suggestionsBox.style.display = 'none';
        }

    } catch (err) {
        console.error("Analysis Error:", err);
    }
}

// Standalone Generator Logic
generateBtn.addEventListener('click', async () => {
    const type = genType.value;
    try {
        const response = await fetch('/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type })
        });
        const data = await response.json();
        genPassText.innerText = data.password;
        genResult.style.display = 'flex';
    } catch (err) {
        console.error("Generation Error:", err);
    }
});

copyGenBtn.addEventListener('click', () => {
    const pass = genPassText.innerText;
    navigator.clipboard.writeText(pass).then(() => {
        const originalText = copyGenBtn.innerHTML;
        copyGenBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
        setTimeout(() => {
            copyGenBtn.innerHTML = originalText;
        }, 2000);
    });
});

function resetUI() {
    document.body.className = '';
    strengthBar.style.width = '0%';
    strengthText.innerText = "Enter password";
    strengthText.style.color = 'var(--text-secondary)';
    scoreText.innerText = "0/100";
    suggestionsBox.style.display = 'none';
    entropyVal.innerText = "0";
    hashScore.innerText = "0%";
    hashPreview.innerText = "SHA-256 Analysis: [Awaiting Input]";

    Object.values(checkElements).forEach(el => {
        el.classList.remove('valid');
        el.querySelector('i').className = 'fas fa-circle-notch';
    });
    checkElements.dictionary.innerHTML = '<i class="fas fa-circle-notch"></i> Not Leaked';
}

function copyToInput(val) {
    passwordInput.value = val;
    updateLocalChecks(val);
    analyzePassword(val);
}

toggleVisibility.addEventListener('click', () => {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    toggleVisibility.querySelector('i').className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
});
