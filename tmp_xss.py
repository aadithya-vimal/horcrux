import re
js = open(r'C:\Users\aadit\AppData\Local\Temp\jsmain.js', encoding='utf-8',
          errors='replace').read()
for pat in (r"bypassSecurityTrust\w*", r"\.innerHTML\s*=\s*[^\n]{0,120}",
            r"queryParams[^;]{0,140}", r"outerHTML"):
    print("=== ", pat)
    ms = list(re.finditer(pat, js))[:6]
    for m in ms:
        print("   ", repr(js[max(0, m.start() - 60):m.end() + 80])[:200])
    if not ms:
        print("    none")
