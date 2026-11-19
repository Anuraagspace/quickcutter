"""Profanity detection, censoring, and audio bleeping for Quick Cutter."""
import re
from typing import List, Dict, Any, Tuple

# Common English and Hindi profanities / slurs / offensive words
PROFANITY_WORDS = {
    # English
    "fuck", "fucking", "fucked", "fucker", "fuckers", "fucks", "motherfucker", "motherfucking",
    "shit", "shitty", "shitting", "shits", "bullshit", "horseshit", "dipshit",
    "bitch", "bitches", "bitching", "bitchy",
    "ass", "asshole", "assholes", "dumbass", "jackass", "badass",
    "bastard", "bastards",
    "cunt", "cunts",
    "dick", "dicks", "dickhead", "dickheads",
    "pussy", "pussies",
    "cock", "cocks", "cocksucker",
    "slut", "sluts",
    "whore", "whores",
    "nigger", "nigga", "niggers", "niggas",
    "fag", "faggot", "faggots",
    "damn", "damned", "goddamn", "goddamned",
    "piss", "pissed", "pissing",
    # Hindi / Hinglish
    "chutiya", "chutiye", "chutiyapa", "choot", "chootiya",
    "madarchod", "madar chod", "mc",
    "bhenchod", "behenchod", "bc", "bhen chod",
    "gaand", "gand", "gandu", "gaandu",
    "bhosdike", "bhosadike", "bhosdi", "bhosda",
    "harami", "haraami",
    "kamina", "kamine", "kaminey",
    "randi", "raandi",
    "lode", "laude", "lavde", "lund", "lodu",
    "saala", "saale", "sale",
    "tatte", "tatta",
    "jhant", "jhaant",
}

# Compile pattern for word boundary matching
_CLEAN_RE = re.compile(r"[^\w]", re.UNICODE)


def normalize(word: str) -> str:
    """Lowercase and strip punctuation."""
    return _CLEAN_RE.sub("", str(word).lower())


def is_profane(word: str) -> bool:
    """True if word is in the profanity dictionary."""
    clean = normalize(word)
    if not clean:
        return False
    if clean in PROFANITY_WORDS:
        return True
    # Check if starts with common root
    for p in ("fuck", "shit", "bitch", "chutiya", "madarchod", "bhenchod", "bhosdi", "asshole"):
        if clean.startswith(p):
            return True
    return False


def censor_word(word: str) -> str:
    """Censors a word: 'fuck' -> 'f***', 'bitch' -> 'b****', preserving punctuation."""
    raw = str(word)
    clean = normalize(raw)
    if not is_profane(clean):
        return raw
    if len(clean) <= 2:
        censored_clean = clean[0] + "*"
    else:
        censored_clean = clean[0] + "*" * (len(clean) - 1)
    
    # Replace the clean portion inside raw
    m = re.search(r"[A-Za-z0-9\u0900-\u097F]+", raw)
    if m:
        return raw[:m.start()] + censored_clean + raw[m.end():]
    return censored_clean


def find_profanities(words: List[Dict[str, Any]], start: float = 0.0, end: float = 999999.0) -> List[Dict[str, Any]]:
    """Returns list of profane words with timestamps within [start, end]."""
    out = []
    for w in words:
        s = float(w.get("s", 0.0))
        e = float(w.get("e", 0.0))
        if s >= start - 0.1 and s <= end + 0.1:
            if is_profane(w.get("w", "")):
                out.append({"w": w.get("w", ""), "s": s, "e": max(e, s + 0.25)})
    return out


def censor_transcript(words: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Returns a copy of words with profane words masked."""
    out = []
    for w in words:
        item = dict(w)
        if is_profane(item.get("w", "")):
            item["w"] = censor_word(item["w"])
            if "sub" in item and is_profane(item["sub"]):
                item["sub"] = censor_word(item["sub"])
        out.append(item)
    return out


def make_bleep_audio_filter(profanities: List[Dict[str, Any]], clip_start: float, clip_dur: float) -> str:
    """Generates an FFmpeg complex filter segment that mutes and plays a 1000Hz bleep tone over profanities.
    Assumes incoming audio stream is [0:a:0] and produces [aout]."""
    if not profanities:
        return "[0:a:0]loudnorm=I=-14:TP=-1.5:LRA=11[aout];"
    
    # Calculate intervals relative to clip_start
    intervals = []
    for p in profanities:
        s = max(0.0, p["s"] - clip_start - 0.05)
        e = min(clip_dur, p["e"] - clip_start + 0.05)
        if e > s:
            intervals.append((round(s, 2), round(e, 2)))
    
    if not intervals:
        return "[0:a:0]loudnorm=I=-14:TP=-1.5:LRA=11[aout];"
    
    between_expr = "+".join(f"between(t,{s},{e})" for s, e in intervals)
    
    # Filtergraph:
    # 1. Mute original audio during profanity
    # 2. Generate 1000Hz sine wave matching clip duration
    # 3. Only enable sine wave during profanity
    # 4. Mix muted audio and bleep tone, then loudnorm
    fg = (
        f"[0:a:0]volume=enable='{between_expr}':volume=0[muted_voice];"
        f"sine=frequency=1000:duration={clip_dur:.2f}[bleep_raw];"
        f"[bleep_raw]volume=enable='{between_expr}':volume=0.35,volume=enable='not({between_expr})':volume=0[bleep_toned];"
        f"[muted_voice][bleep_toned]amix=inputs=2:dropout_transition=0,loudnorm=I=-14:TP=-1.5:LRA=11[aout];"
    )
    return fg
