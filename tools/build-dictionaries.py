"""
Builds js/dictionaries.js and js/wordlists.js from open data sets.

Sources (see THIRD_PARTY.md for licenses):
  - @zxcvbn-ts/language-common 4.2.0: leaked passwords ranked by frequency
    (Mark Burnett's 10M passwords, public domain), keyboard adjacency graphs
    (MIT) and the EFF long word list (CC BY 4.0).
  - @zxcvbn-ts/language-es-es 4.1.3 and @zxcvbn-ts/language-en 4.1.2: common
    words from OpenSubtitles 2024 via OPUS (ODC-BY), first names and surnames (MIT).
  - Honduras list: written by hand for this project.

Usage: python3 tools/build-dictionaries.py <folder with the three unpacked npm packages>
"""
import json, re, sys, unicodedata, os

SRC = sys.argv[1]
def load(pkg, name):
    return json.load(open(os.path.join(SRC, pkg, 'package', 'src', name), encoding='utf-8'))

COMMON = 'zxcvbn-ts-language-common-4.2.0'
ES = 'zxcvbn-ts-language-es-es-4.1.3'
EN = 'zxcvbn-ts-language-en-4.1.2'

def fold(w):
    """lowercase, no accents (contraseña -> contrasena), same as the analyzer."""
    return ''.join(c for c in unicodedata.normalize('NFD', w.lower()) if unicodedata.category(c) != 'Mn')

def ranked(words, limit, minlen=3):
    out, seen = [], set()
    for w in words:
        f = fold(w)
        if len(f) < minlen or not re.fullmatch(r'[a-z0-9]+', f) or f in seen:
            continue
        seen.add(f); out.append(f)
        if len(out) >= limit: break
    return out

# Words Honduran passwords use a lot. Ordered roughly from most to least likely.
HONDURAS = """honduras catracho catracha olimpia motagua marathon realespana hondureno hondurena tegucigalpa tegus
sanpedrosula sampedrosula sps lempira lempiras comayagua comayaguela choluteca laceiba ceiba copan copanruinas
ocotepeque santarosa santabarbara olancho juticalpa danli elparaiso yoro progreso puertocortes cortes atlantida
colon trujillo roatan utila guanaja islasdelabahia intibuca lapaz valle nacaome amapala gracias siguatepeque
juticalpa tocoa catacamas lalima villanueva choloma sanlorenzo morazan francisco franciscomorazan
cipote cipota maje chele pisto chamba birria baleada baleadas catrachos guanaco bicho bicha jaña cheque macanudo
pinol pupusa tamal nacatamal semita yuca chicharron chilero vos ideay puchica chepe tegucigalpamdc
olimpista motagüense azul azules leones aguilas merengues verdolaga albo ciclon
honduras504 catracho504 hn504 504 hnd jesucristo diosmeama diosesbueno bendecido bendecida jehova aleluya amen
""".split()

# Typical names in Honduras that the Spain list misses.
HN_NAMES = """kevin brayan bryan josue cristian christian jonathan jefferson anderson dilcia karla wendy yessenia lesly
nohemy yolanda gloria marlen marleny merlin dayana daniela valeria valentina camila fernanda nicole genesis
cesia keila keyla allison alison ashley estefany stefany andrea alejandra mariela marvin selvin elvin edwin
wilmer nelson wilson elmer lester denis dennis osman oscar orlin olvin ever cesar mario ramon santos lenin
yeferson yoselin joselyn jocelyn katherine catherine scarleth ingrid suyapa lempira asaf""".split()

# Words nobody wants in a generated passphrase.
BLOCK = re.compile(r'(mierd|puta|puto|cabron|carajo|culo|coño|pene|polla|vagin|sexo|sexual|violar|viola|suicid|matar|mato|matan|muert|morir|muere|asesin|cadaver|sangr|droga|cocain|mataste|disparo|dispar|pistola|arma|bomba|guerra|odio|maldit|joder|jodid|follar|imbecil|idiota|estupid|perra|zorra|caca|marica|negr|gord|feo|fea|diablo|demonio|infiern|cancer|tumor|enferm|herida|dolor|cruel|tortur|secuestr|robar|robo|ladron|crimen|delit|carcel|preso|policia|juicio|tumba|funeral|entierr|cementer|esclav|bastard|maldad|traidor|veneno|pecado|nalga|teta|desnud|besar|besame|amante|tirot|balac|balaz|bala|golpe|pelea|cuchill|navaja|rehen|explot|ahorc|ahog|apunal|puñal|degoll|mutil|cadaver|forense|autopsia|fantasm|maldic|brujer|bruja|satan|pistol|rifle|escopet|misil|terror|atentad|abus|acos|prostitu|burdel|stripper|borrach|alcohol|cerveza|vodka|whisky|tequila|fumar|cigarr|marihuan|heroin|dispara|matanz|masacr|herido|heridas|victim|cadena|carcel|celda|condena|verdug|ejecut|suicid|lujuria|orgasm|erotic|porno|pecho|senos|trasero|culito|gay|lesbian|vomit|orina|mear|cagar|pedo|mocos|basura|asco|odias|odiar|perdedor|fracas|tonto|tonta|bobo|loco|loca|demente|psicopat|enfermo|muerto|mortal|morgue|ataud|luto|viuda)')

BLOCK_START = re.compile(r'(mata|matad|muer|roba|robe|robo|hiere|hiri|pega|golpea|odia|mient|engan|traic)')

# Skip most verb forms (hicieron, tendrias...): nouns and adjectives are easier to picture and remember.
VERB_END = re.compile(r'(aron|ieron|ando|iendo|aste|iste|amos|emos|imos|aba|abas|aban|rias|rian|ria|ias|ian|ras|ran|iera|ieras|ase|iese|arme|arte|arlo|arla|erlo|irlo|selo|ais|eis|ar|er|ir)$')

def passphrase_es(es_words, en_words, names, limit=4096):
    en_set = set(fold(w) for w in en_words[:25000])
    name_set = set(names)
    out = []
    for w in es_words:
        if not re.fullmatch(r'[a-z]{4,8}', w):  # no accents or ñ: easy to type anywhere
            continue
        if w in en_set or w in name_set or BLOCK.search(w) or BLOCK_START.match(w) or VERB_END.search(w):
            continue
        out.append(w)
        if len(out) == limit: break
    return out

def main():
    passwords = ranked(load(COMMON, 'passwords.json'), 12000, minlen=1)
    es_common = load(ES, 'commonWords.json')
    en_common = load(EN, 'commonWords.json')
    es_words = ranked(es_common, 14000)
    en_words = ranked(en_common, 12000)
    names = ranked(HN_NAMES + load(ES, 'firstnames.json') + load(EN, 'firstnames.json')[:0], 2500)
    en_names = ranked(load(EN, 'firstnames.json'), 2000)
    surnames = ranked(load(ES, 'lastnames.json'), 4000)
    honduras = ranked([fold(w) for w in HONDURAS], 1000, minlen=3)
    graphs = load(COMMON, 'adjacencyGraphs.json')

    all_names = ranked(names + en_names, 4000)
    eff = load(COMMON, 'diceware.json')
    assert len(eff) == 7776
    es_pp = passphrase_es(ranked(es_common, 60000, minlen=4), en_common, set(all_names) | set(ranked(load(ES, 'lastnames.json'), 8000)))
    assert len(es_pp) == 4096, len(es_pp)

    header = '/*!\n * SworfishGuard — dictionaries for the password analyzer (generated by tools/build-dictionaries.py, do not edit).\n' \
             ' * Leaked passwords: Mark Burnett 10M (public domain). Common words: OpenSubtitles 2024 via OPUS (ODC-BY).\n' \
             ' * Names, surnames, keyboard graphs: zxcvbn-ts (MIT). Honduras list: this project. See THIRD_PARTY.md.\n */\n'
    body = {
        'passwords': ' '.join(passwords), 'es': ' '.join(es_words), 'en': ' '.join(en_words),
        'names': ' '.join(all_names), 'surnames': ' '.join(surnames), 'honduras': ' '.join(honduras),
    }
    js = header + "(function (root) {\n  'use strict';\n  var LISTS = " + json.dumps(body, ensure_ascii=False) + ";\n" \
         "  var GRAPHS = " + json.dumps({'qwerty': graphs['qwerty'], 'keypad': graphs['keypad']}, separators=(',', ':')) + ";\n" \
         "  var api = { LISTS: LISTS, GRAPHS: GRAPHS };\n" \
         "  root.SworfishGuard = root.SworfishGuard || {};\n  root.SworfishGuard.dictionaries = api;\n" \
         "  if (typeof module !== 'undefined' && module.exports) module.exports = api;\n})(typeof window !== 'undefined' ? window : globalThis);\n"
    open('js/dictionaries.js', 'w', encoding='utf-8').write(js)

    wl = '/*!\n * SworfishGuard — word lists for passphrases (generated by tools/build-dictionaries.py, do not edit).\n' \
         ' * English: EFF long word list, 7776 words = 12.9 bits per word (CC BY 4.0, Electronic Frontier Foundation).\n' \
         ' * Spanish: 4096 common words from OpenSubtitles 2024 via OPUS (ODC-BY) = 12 bits per word,\n' \
         ' *   4-8 letters, no accents, no names, no English words, filtered for offensive or violent words.\n */\n' \
         "(function (root) {\n  'use strict';\n  var WORDS = {\n    es: " + json.dumps(' '.join(es_pp)) + ".split(' '),\n" \
         "    en: " + json.dumps(' '.join(eff)) + ".split(' ')\n  };\n" \
         "  Object.freeze(WORDS.es); Object.freeze(WORDS.en); Object.freeze(WORDS);\n" \
         "  root.SworfishGuard = root.SworfishGuard || {};\n  root.SworfishGuard.words = WORDS;\n" \
         "  if (typeof module !== 'undefined' && module.exports) module.exports = WORDS;\n})(typeof window !== 'undefined' ? window : globalThis);\n"
    open('js/wordlists.js', 'w', encoding='utf-8').write(wl)
    print('passwords', len(passwords), 'es', len(es_words), 'en', len(en_words), 'names', len(all_names),
          'surnames', len(surnames), 'honduras', len(honduras), '| passphrase es', len(es_pp), 'en', len(eff))
    print('dictionaries.js', os.path.getsize('js/dictionaries.js'), 'wordlists.js', os.path.getsize('js/wordlists.js'))
    print('sample es passphrase words:', es_pp[::160])

main()
