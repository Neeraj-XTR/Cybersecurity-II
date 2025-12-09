"""
CLI USEcase code
python caesarcypher_decrypter.py --text "fwefwhfoi fiwnfiowfjw" --method best --top 2 --show-keys
python caesarcypher_decrypter.py --file text.txt --method brute --show-keys

"""

from typing import Tuple, List, Dict
import string
import argparse
import sys
import math

ALPHABET_LOWER = string.ascii_lowercase
ALPHABET_UPPER = string.ascii_uppercase

# English letter frequency (relative) from typical corpora
ENGLISH_FREQ = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074
}

def shift_char(c: str, shift: int) -> str:
    """Shift a single character by shift positions (negative for left)."""
    if c.islower():
        idx = ALPHABET_LOWER.index(c)
        return ALPHABET_LOWER[(idx + shift) % 26]
    if c.isupper():
        idx = ALPHABET_UPPER.index(c)
        return ALPHABET_UPPER[(idx + shift) % 26]
    return c

def caesar_shift(text: str, key: int) -> str:
    """Return text shifted by key (encrypt if key positive, decrypt if negative)."""
    return ''.join(shift_char(c, key) for c in text)

def brute_force_decrypt(ciphertext: str) -> List[Tuple[int, str]]:
    """Return a list of (key, plaintext) for all 26 possible keys."""
    results = []
    for k in range(26):
        # For Caesar, decrypt by shifting left by k -> equivalent to shifting by -k
        plaintext = caesar_shift(ciphertext, -k)
        results.append((k, plaintext))
    return results

def frequency_score(text: str) -> float:
    """
    Score text by comparing letter frequency distribution to English.
    Higher score => closer to English distribution.
    Uses cosine similarity on distributions.
    """
    text = text.lower()
    counts = {ch: 0 for ch in ALPHABET_LOWER}
    total = 0
    for ch in text:
        if ch in counts:
            counts[ch] += 1
            total += 1
    if total == 0:
        return -math.inf
    # compute vectors and cosine similarity
    vec_text = [counts[ch] / total for ch in ALPHABET_LOWER]
    vec_lang = [ENGLISH_FREQ[ch] for ch in ALPHABET_LOWER]
    dot = sum(a*b for a,b in zip(vec_text, vec_lang))
    norm_text = math.sqrt(sum(a*a for a in vec_text))
    norm_lang = math.sqrt(sum(b*b for b in vec_lang))
    if norm_text == 0 or norm_lang == 0:
        return -math.inf
    return dot / (norm_text * norm_lang)

def best_guess_decrypt(ciphertext: str, top_n: int = 1) -> List[Tuple[int, str, float]]:
    """
    Return top_n candidate decryptions ranked by frequency_score.
    Each item: (key, plaintext, score)
    """
    candidates = []
    for k, plaintext in brute_force_decrypt(ciphertext):
        score = frequency_score(plaintext)
        candidates.append((k, plaintext, score))
    candidates.sort(key=lambda x: x[2], reverse=True)
    return candidates[:top_n]

def interactive_cli():
    parser = argparse.ArgumentParser(
        prog="caesarcracker",
        description="Decrypt Caesar ciphers via brute-force and frequency analysis."
    )
    parser.add_argument("-t", "--text", help="Ciphertext string to decrypt.")
    parser.add_argument("-f", "--file", help="Path to file with ciphertext.")
    parser.add_argument("-m", "--method", choices=["brute","best"], default="best",
                        help="Method: 'brute' show all 26 candidates; 'best' show top candidate(s).")
    parser.add_argument("-n", "--top", type=int, default=3, help="Number of top candidates to show (best).")
    parser.add_argument("--show-keys", action="store_true", help="Show key numeric values with candidates.")
    args = parser.parse_args()

    if not args.text and not args.file:
        print("Either --text or --file is required. Use -h for help.")
        sys.exit(1)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            ciphertext = fh.read()
    else:
        ciphertext = args.text

    ciphertext = ciphertext.strip()
    if args.method == "brute":
        results = brute_force_decrypt(ciphertext)
        for k, p in results:
            prefix = f"[key={k}] " if args.show_keys else ""
            print(prefix + p)
    else:
        best = best_guess_decrypt(ciphertext, top_n=args.top)
        for k, p, s in best:
            prefix = f"[key={k}] " if args.show_keys else ""
            print(f"{prefix}{p}\nscore={s:.4f}\n")

if __name__ == "__main__":
    interactive_cli()