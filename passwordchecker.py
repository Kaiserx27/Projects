# Advanced Password Strength Tester - Tkinter Desktop App
# Features:
# - Entropy calculation
# - Checks: length, character variety, dictionary/common passwords, repeated patterns, sequences
# - Suggestions and tips for improving password
# - Password generator (customizable)
# - Visual score meter and color feedback
# - Copy to clipboard button

import tkinter as tk
from tkinter import ttk, messagebox
import random
import math
import string

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "football", "monkey", "letmein", "dragon", "111111",
    "baseball", "iloveyou", "trustno1", "1234567", "sunshine"
}

def calc_entropy(password: str) -> float:
    """Estimate entropy (bits) based on character set size and length."""
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    # count unique non-alnum symbols roughly as 32
    if any(not c.isalnum() for c in password):
        pool += 32
    # fallback: unique count
    if pool == 0:
        pool = len(set(password))
    entropy = math.log2(pool) * len(password) if pool > 0 else 0.0
    return round(entropy, 2)

def has_repeated_patterns(p: str) -> bool:
    """Detect simple repeated chunks like 'abcabc', '123123' or same char repeated."""
    if len(p) < 4:
        return False
    # same char repeated
    if len(set(p)) == 1:
        return True
    # check for repeated half
    for size in range(1, len(p)//2 + 1):
        if len(p) % size == 0:
            chunk = p[:size]
            if chunk * (len(p)//size) == p:
                return True
    return False

def has_sequences(p: str) -> bool:
    """Detect ascending or descending sequences of 3+ characters or digits."""
    if len(p) < 3:
        return False
    s = p.lower()
    for i in range(len(s)-2):
        a, b, c = s[i], s[i+1], s[i+2]
        if a.isalpha() and b.isalpha() and c.isalpha():
            if ord(b) == ord(a) + 1 and ord(c) == ord(b) + 1:
                return True
            if ord(b) == ord(a) - 1 and ord(c) == ord(b) - 1:
                return True
        if a.isdigit() and b.isdigit() and c.isdigit():
            if int(b) == int(a) + 1 and int(c) == int(b) + 1:
                return True
            if int(b) == int(a) - 1 and int(c) == int(b) - 1:
                return True
    return False

def score_password(p: str) -> dict:
    """Return a detailed scoring dict with components and suggestions."""
    length = len(p)
    entropy = calc_entropy(p)
    suggestions = []
    score = 0
    # Length scoring
    if length == 0:
        suggestions.append("Password is empty.")
    elif length < 8:
        suggestions.append("Make the password at least 8 characters long.")
        score -= 2
    elif 8 <= length < 12:
        score += 1
    elif 12 <= length < 16:
        score += 2
    else:
        score += 3
    # Variety scoring
    sets = 0
    if any(c.islower() for c in p):
        sets += 1
    if any(c.isupper() for c in p):
        sets += 1
    if any(c.isdigit() for c in p):
        sets += 1
    if any(not c.isalnum() for c in p):
        sets += 1
    score += (sets - 1)  # more variety -> better
    if sets < 3:
        suggestions.append("Use a mix of lowercase, uppercase, digits and symbols.")
    # Entropy contribution
    if entropy < 28:
        score -= 2
        suggestions.append("Very low entropy; avoid obvious patterns and short length.")
    elif entropy < 50:
        score += 0
        suggestions.append("Moderate entropy; increasing length helps more than symbols.")
    else:
        score += 2
    # Common password check
    if p.lower() in COMMON_PASSWORDS:
        suggestions.append("This password is a common password; don't use it.")
        score -= 5
    # Repeated patterns / sequences
    if has_repeated_patterns(p):
        suggestions.append("Password contains repeated patterns; make it more random.")
        score -= 2
    if has_sequences(p):
        suggestions.append("Password contains sequences (abc, 123); avoid predictable sequences.")
        score -= 2
    # Personal info pattern checks (rudimentary)
    if any(token in p.lower() for token in ["name", "john", "doe", "pass", "user"]):
        suggestions.append("Avoid using common words or personal identifiers.")
        score -= 1
    # Cap score between 0 and 10 then normalize to percent
    numeric = max(0, min(10, 5 + score))
    percent = int((numeric / 10) * 100)
    # Tier
    if percent < 30:
        tier = "Very weak"
    elif percent < 50:
        tier = "Weak"
    elif percent < 70:
        tier = "Fair"
    elif percent < 85:
        tier = "Good"
    else:
        tier = "Strong"
    return {
        "length": length,
        "entropy": entropy,
        "sets": sets,
        "score_raw": score,
        "score_norm": numeric,
        "percent": percent,
        "tier": tier,
        "suggestions": suggestions
    }

def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True) -> str:
    """Generate a random password from requested character classes."""
    pool = ""
    if use_lower:
        pool += string.ascii_lowercase
    if use_upper:
        pool += string.ascii_uppercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += "!@#$%^&*()-_+=[]{};:,<.>/?"
    if not pool:
        pool = string.ascii_letters + string.digits
    # ensure at least one of each selected class
    password = []
    if use_lower:
        password.append(random.choice(string.ascii_lowercase))
    if use_upper:
        password.append(random.choice(string.ascii_uppercase))
    if use_digits:
        password.append(random.choice(string.digits))
    if use_symbols:
        password.append(random.choice("!@#$%^&*()-_+=[]{};:,<.>/?"))
    while len(password) < length:
        password.append(random.choice(pool))
    random.shuffle(password)
    return "".join(password[:length])

# --- GUI ---
class PasswordTesterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Password Strength Tester")
        self.geometry("760x480")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        pad = 8
        main = ttk.Frame(self, padding=pad)
        main.pack(fill=tk.BOTH, expand=True)
        # Input
        input_frame = ttk.LabelFrame(main, text="Password input", padding=pad)
        input_frame.pack(side=tk.TOP, fill=tk.X, padx=pad, pady=pad)
        self.pw_var = tk.StringVar()
        pw_entry = ttk.Entry(input_frame, textvariable=self.pw_var, show="*", width=60)
        pw_entry.pack(side=tk.LEFT, padx=(0, 10))
        pw_entry.bind("<KeyRelease>", lambda e: self.evaluate())
        ttk.Button(input_frame, text="Show", width=6, command=self._toggle_show).pack(side=tk.LEFT)
        ttk.Button(input_frame, text="Copy", width=6, command=self._copy_to_clipboard).pack(side=tk.LEFT)
        ttk.Button(input_frame, text="Generate", width=8, command=self._generate_and_fill).pack(side=tk.LEFT)
        # Score display
        score_frame = ttk.LabelFrame(main, text="Strength", padding=pad)
        score_frame.pack(side=tk.TOP, fill=tk.X, padx=pad, pady=pad)
        self.score_bar = ttk.Progressbar(score_frame, length=500, maximum=100)
        self.score_bar.pack(side=tk.LEFT, padx=(0,10))
        self.tier_label = ttk.Label(score_frame, text="Tier: -", width=20)
        self.tier_label.pack(side=tk.LEFT)
        # Details & suggestions
        detail_frame = ttk.Frame(main, padding=pad)
        detail_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=pad, pady=pad)
        left = ttk.Frame(detail_frame)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = ttk.Frame(detail_frame)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        # Stats
        stats_box = ttk.LabelFrame(left, text="Stats", padding=pad)
        stats_box.pack(fill=tk.BOTH, expand=True, pady=(0, pad))
        self.stats_text = tk.Text(stats_box, height=8, wrap=tk.WORD)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        # Suggestions
        sug_box = ttk.LabelFrame(left, text="Suggestions", padding=pad)
        sug_box.pack(fill=tk.BOTH, expand=True)
        self.sug_text = tk.Text(sug_box, height=8, wrap=tk.WORD)
        self.sug_text.pack(fill=tk.BOTH, expand=True)
        # Generator options
        gen_box = ttk.LabelFrame(right, text="Generator", padding=pad)
        gen_box.pack(fill=tk.BOTH, expand=True, padx=(10,0))
        self.gen_len = tk.IntVar(value=16)
        ttk.Label(gen_box, text="Length:").pack(anchor=tk.W)
        ttk.Spinbox(gen_box, from_=6, to=64, textvariable=self.gen_len, width=6).pack(anchor=tk.W)
        self.var_lower = tk.BooleanVar(value=True)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(gen_box, text="lowercase", variable=self.var_lower).pack(anchor=tk.W)
        ttk.Checkbutton(gen_box, text="UPPERCASE", variable=self.var_upper).pack(anchor=tk.W)
        ttk.Checkbutton(gen_box, text="digits", variable=self.var_digits).pack(anchor=tk.W)
        ttk.Checkbutton(gen_box, text="symbols", variable=self.var_symbols).pack(anchor=tk.W)
        ttk.Button(gen_box, text="Generate & Copy", command=self._generate_and_copy).pack(pady=(8,0))
        # Footer (about / help)
        footer = ttk.Label(main, text="Tip: use a passphrase of 4+ random words for high memorability and entropy.", anchor=tk.CENTER)
        footer.pack(side=tk.BOTTOM, fill=tk.X, pady=(6,0))
        # initial evaluate
        self._show_pw = False
        self.evaluate()

    def _toggle_show(self):
        # toggle show/hide password entry
        entry = None
        # find entry by traversing widget tree
        for child in self.winfo_children():
            for g in child.winfo_children():
                if isinstance(g, ttk.Entry):
                    entry = g
        if not entry:
            return
        self._show_pw = not self._show_pw
        entry.config(show="" if self._show_pw else "*")

    def _copy_to_clipboard(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showinfo("Copy", "No password to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(pw)
        messagebox.showinfo("Copy", "Password copied to clipboard.")

    def _generate_and_fill(self):
        pw = generate_password(
            length=self.gen_len.get(),
            use_lower=self.var_lower.get(),
            use_upper=self.var_upper.get(),
            use_digits=self.var_digits.get(),
            use_symbols=self.var_symbols.get()
        )
        self.pw_var.set(pw)
        self.evaluate()

    def _generate_and_copy(self):
        self._generate_and_fill()
        self._copy_to_clipboard()

    def evaluate(self):
        p = self.pw_var.get()
        res = score_password(p)
        # update progress bar and tier label
        self.score_bar['value'] = res['percent']
        self.tier_label.config(text=f"Tier: {res['tier']} ({res['percent']}%)")
        # colorize progressbar via style
        style = ttk.Style()
        if res['percent'] < 30:
            style.configure("red.Horizontal.TProgressbar", troughcolor='white', background='red')
            self.score_bar.config(style="red.Horizontal.TProgressbar")
        elif res['percent'] < 50:
            style.configure("orange.Horizontal.TProgressbar", troughcolor='white', background='orange')
            self.score_bar.config(style="orange.Horizontal.TProgressbar")
        elif res['percent'] < 70:
            style.configure("yellow.Horizontal.TProgressbar", troughcolor='white', background='yellow')
            self.score_bar.config(style="yellow.Horizontal.TProgressbar")
        elif res['percent'] < 85:
            style.configure("green.Horizontal.TProgressbar", troughcolor='white', background='green')
            self.score_bar.config(style="green.Horizontal.TProgressbar")
        else:
            style.configure("darkgreen.Horizontal.TProgressbar", troughcolor='white', background='darkgreen')
            self.score_bar.config(style="darkgreen.Horizontal.TProgressbar")
        # update stats text
        self.stats_text.configure(state=tk.NORMAL)
        self.stats_text.delete("1.0", tk.END)
        stats_msg = (
            f"Length: {res['length']}\n"
            f"Character sets used: {res['sets']} (lower/upper/digits/symbols)\n"
            f"Entropy estimate: {res['entropy']} bits\n"
            f"Raw score: {res['score_raw']}\n"
        )
        self.stats_text.insert(tk.END, stats_msg)
        self.stats_text.configure(state=tk.DISABLED)
        # suggestions
        self.sug_text.configure(state=tk.NORMAL)
        self.sug_text.delete("1.0", tk.END)
        if res['suggestions']:
            for s in res['suggestions']:
                self.sug_text.insert(tk.END, "• " + s + "\n")
        else:
            self.sug_text.insert(tk.END, "No suggestions — strong password!\n")
        self.sug_text.configure(state=tk.DISABLED)

if __name__ == "__main__":
    app = PasswordTesterApp()
    app.mainloop()
