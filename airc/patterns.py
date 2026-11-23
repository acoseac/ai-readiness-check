"""File-name hints for content that humanitarian and civil-society organisations most need to
protect. Only names are checked, never file contents. English, French, Spanish, Arabic and some
German. Arabic words are matched inside longer words too, so prefixes such as al- still match."""

import re
import unicodedata

# Each category maps to regular expressions matched against a folded file name
# (lower case, accents removed, separators turned into spaces).
CATEGORIES = {
    "identity documents": [
        r"pasaportes?", r"cedulas?( de identidad)?", r"documentos? de identidad", r"dni",
        r"\w*جواز\w*", r"\w*هوية\w*",
        r"passports?", r"passeports?", r"reisepass", r"id cards?", r"identity cards?",
        r"carte d identite", r"cartes d identite", r"residence permits?", r"titres? de sejour",
        r"permis de sejour", r"aufenthaltsbewilligung", r"birth certificates?",
        r"actes? de naissance", r"id scans?", r"id copies",
    ],
    "beneficiaries and protection": [
        r"refugiados?", r"solicitantes? de asilo", r"asilo", r"notas? de caso", r"expedientes?",
        r"victimas?", r"proteccion infantil", r"sobrevivientes?",
        r"\w*مستفيد\w*", r"\w*لاجئ\w*", r"\w*لجوء\w*", r"\w*ناجي\w*",
        r"beneficiar\w*", r"benefici\w*", r"refugees?", r"refugies?", r"fluchtling\w*",
        r"asylum", r"asile", r"case ?notes?", r"case ?files?", r"case ?management",
        r"protection cases?", r"dossiers? individuels?", r"registration lists?",
        r"liste d enregistrement", r"gbv", r"sgbv", r"vbg", r"survivors?", r"survivant\w*",
        r"safeguarding", r"child protection", r"protection de l enfance", r"psea",
        r"incident reports?", r"rapports? d incident", r"vulnerab\w*",
    ],
    "health": [
        r"salud", r"historias? clinicas?", r"\w*طبي\w*", r"\w*صحي\w*",
        r"medical", r"medicaux", r"medicale", r"health records?", r"sante", r"hiv", r"vih",
        r"psychosocial", r"mhpss", r"diagnos\w*", r"patients?",
    ],
    "staff and pay": [
        r"salarios?", r"nominas?", r"recursos humanos", r"\w*رواتب\w*", r"\w*راتب\w*",
        r"salar(y|ies)", r"salaires?", r"payroll", r"paie", r"lohn\w*", r"hr", r"rh",
        r"personnel files?", r"dossiers? du personnel", r"employment contracts?",
        r"contrats? de travail", r"performance (review|evaluation)s?", r"disciplinar\w*",
        r"evaluations? annuelles?", r"payslips?", r"fiches? de (paie|salaire)",
    ],
    "finance and donors": [
        r"datos bancarios", r"donantes", r"\w*مانحين\w*",
        r"iban", r"bank details", r"coordonnees bancaires", r"bankverbindung",
        r"donors? lists?", r"liste des donateurs", r"donateurs", r"credit cards?",
    ],
    "meeting notes and transcripts": [
        r"notes by gemini", r"transcripts?", r"transcriptions?", r"meeting recordings?",
        r"recordings?", r"compte rendu", r"verbatim",
    ],
    "credentials": [
        r"contrasenas?", r"\w*كلمة المرور\w*", r"\w*كلمة السر\w*",
        r"passwords?", r"mots? de passe", r"passwort\w*", r"credentials?", r"api keys?",
        r"secrets?", r"logins?",
    ],
}

_COMPILED = {
    cat: re.compile(r"\b(?:" + "|".join(pats) + r")\b") for cat, pats in CATEGORIES.items()
}


def fold(name):
    """Lower-case, strip accents and turn separators into spaces."""
    text = unicodedata.normalize("NFKD", name or "")
    text = "".join(c for c in text if not unicodedata.combining(c)).lower()
    text = re.sub(r"[_\-.,;:()\[\]{}/\\'\"+]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


OWN_WORDS = "your own words"


SHORT_TERM = 4  # terms this long or shorter must match a whole word


def compile_terms(terms):
    """Build a matcher for an organisation's own words (--keywords). Each term is folded like a
    file name and escaped. Longer terms are matched at the start of a word, so 'donor' also
    finds 'donors'. Terms of four characters or fewer must match a whole word, so 'WASH' does
    not match 'Washington' and 'ARC' does not match 'archive'."""
    folded = sorted({fold(t) for t in terms if fold(t)}, key=len, reverse=True)
    if not folded:
        return None
    parts = [re.escape(t) + (r"(?!\w)" if len(t) <= SHORT_TERM else "") for t in folded]
    return re.compile(r"\b(?:" + "|".join(parts) + r")")


def read_terms(path):
    """One term per line; blank lines and lines starting with # are skipped."""
    with open(path, encoding="utf-8-sig") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def hints(name, extra=None):
    """Return the sorted list of sensitive categories a file name suggests. extra is a matcher
    from compile_terms, reported as 'your own words'."""
    folded = fold(name)
    found = [cat for cat, rx in _COMPILED.items() if rx.search(folded)]
    if extra is not None and extra.search(folded):
        found.append(OWN_WORDS)
    return sorted(found)


AI_APP_WORDS = re.compile(
    r"\b(openai|chatgpt|gpt|claude|anthropic|gemini|copilot|perplexity|mistral|otter|"
    r"fireflies|read ai|fathom|tl ?dv|notta|grammarly|jasper|writesonic|notion ai|"
    r"meeting ?(bot|notes|assistant)|transcri\w*|ai)\b"
)


def looks_like_ai_app(name):
    return bool(AI_APP_WORDS.search(fold(name)))
