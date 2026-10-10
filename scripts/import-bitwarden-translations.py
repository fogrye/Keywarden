#!/usr/bin/env python3
"""Fills Sources/Keywarden/Localizable.xcstrings with the Bitwarden clients' translations.

A catalog string takes Bitwarden's translation when its English text matches a message of the
Bitwarden desktop app (or, failing that, the browser extension) at the pinned commit. Those
translations come from Bitwarden's Crowdin project and are GPL-3.0, like Keywarden.

Imported values are marked "translated". Values that are not imported keep their state; AI-written
translations are marked "needs_review" until a person checks them. A value already present is only
replaced when it is "needs_review", so reviewed translations are never overwritten.

Usage: scripts/import-bitwarden-translations.py [--dry-run]
"""
import json, re, subprocess, sys, urllib.request
from pathlib import Path

COMMIT = "e530a0114048a723966ac6d25a26205c6fe089af"
# Bitwarden locale -> Apple language code. Languages Bitwarden has at least 95% translated.
LANGUAGES = {
    "af": "af", "ar": "ar", "az": "az", "be": "be", "bg": "bg", "cs": "cs", "de": "de", "es": "es",
    "et": "et", "fa": "fa", "fi": "fi", "fr": "fr", "hi": "hi", "hr": "hr", "hu": "hu", "id": "id",
    "it": "it", "ja": "ja", "ko": "ko", "nl": "nl", "pl": "pl", "pt_BR": "pt-BR", "pt_PT": "pt-PT",
    "ru": "ru", "sk": "sk", "sr": "sr", "sv": "sv", "ta": "ta", "te": "te", "th": "th", "tr": "tr",
    "uk": "uk", "vi": "vi", "zh_CN": "zh-Hans", "zh_TW": "zh-Hant",
}
APPS = {"desktop": "apps/desktop/src/locales/{}/messages.json",
        "browser": "apps/browser/src/_locales/{}/messages.json"}
ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "Sources/Keywarden/Localizable.xcstrings"
CACHE = Path.home() / "Library/Caches/keywarden-bitwarden-locales" / COMMIT

SPECIFIER = re.compile(r"%(?:\d+\$)?(lld|@)")
TOKEN = re.compile(r"\$([A-Za-z0-9_]+)\$")
UNSAFE = re.compile(r"[$<>*_`\[\]]")


def fetch(app, locale):
    path = CACHE / app / f"{locale}.json"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://raw.githubusercontent.com/bitwarden/clients/{COMMIT}/" + APPS[app].format(locale)
        try:
            data = urllib.request.urlopen(url).read()
        except Exception:
            data = b"{}"
        path.write_bytes(data)
    return json.loads(path.read_text())


def key_form(text):
    """English text compared case- and typography-insensitively, with placeholders abstracted."""
    text = text.replace("’", "'").replace("“", '"').replace("”", '"')
    return TOKEN.sub("\0", SPECIFIER.sub("\0", text)).strip().lower()


def convert(message, english, key):
    """Bitwarden's $NAME$ placeholders, in the order they appear in its English, become our key's
    specifiers in the same order, positional when there are several."""
    ours = SPECIFIER.findall(key)
    order = [t.lower() for t in TOKEN.findall(english)]
    if len(order) != len(ours) or len(set(order)) != len(order):
        return None
    def slot(match):
        name = match.group(1).lower()
        if name not in order:
            raise ValueError(name)
        i = order.index(name)
        return f"%{i + 1}${ours[i]}" if len(ours) > 1 else f"%{ours[i]}"
    try:
        value = TOKEN.sub(slot, message)
    except ValueError:
        return None
    return None if UNSAFE.search(value) else value


def main():
    dry = "--dry-run" in sys.argv
    catalog = json.loads(CATALOG.read_text())
    english = {app: fetch(app, "en") for app in APPS}
    index = {}
    for app in APPS:
        for mid, entry in english[app].items():
            index.setdefault(key_form(entry["message"]), (app, mid))
    imported = {}
    for key, entry in catalog["strings"].items():
        if entry.get("shouldTranslate") is False or key_form(key) not in index:
            continue
        # Counts need plural forms, which Bitwarden's messages don't have.
        if any("variations" in loc for loc in entry.get("localizations", {}).values()):
            continue
        app, mid = index[key_form(key)]
        source = english[app][mid]["message"]
        # Punctuation must agree exactly (a missing full stop can't be patched in every script).
        if source.rstrip()[-1:] in ".?!:…" or key.rstrip()[-1:] in ".?!:…":
            if source.rstrip()[-1:] != key.rstrip()[-1:]:
                continue
        for locale, language in LANGUAGES.items():
            message = fetch(app, locale).get(mid, {}).get("message")
            if not message or message == source:
                continue
            value = convert(message, source, key)
            if value is None:
                continue
            current = entry.get("localizations", {}).get(language, {}).get("stringUnit")
            if current and current["state"] != "needs_review":
                continue
            entry.setdefault("localizations", {})[language] = {
                "stringUnit": {"state": "translated", "value": value}}
            imported[language] = imported.get(language, 0) + 1
    for language in sorted(imported):
        print(f"{language}: {imported[language]} imported")
    if not dry:
        CATALOG.write_text(json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True,
                                      separators=(",", " : ")) + "\n")


if __name__ == "__main__":
    main()
