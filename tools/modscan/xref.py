import sys, zipfile, os, re
from collections import defaultdict
PK = {
 'Secret': b'com/himitsu/secret', 'ForeverLoveSword': b'com/wzz/forever_love_sword',
 'ArcaneVortex(ErChien)': b'com/erchien/arcanevortex', 'ArcaneVortex(Luoee)': b'com/luoee/arcanevortex',
 'Buer': b'com/luoyanyuchen/buer', 'Pig2': b'kakiku/pig2mod', 'SuperSteve': b'plz/lizi/supersteve',
 'apphhzpLIB': b'apphhzp/lib', 'EntityEraserRe': b'net/apphhzp/entityeraser', 'BlackSun': b'cn/blockforge/dyingsol',
 'Echoes': b'net/mcreator/echoesoflegend', 'Witheria': b'net/mcreator/witheria', 'OttoWorld': b'cn/blockforge/generated/ottoworld',
 'PrimordialEnd': b'cn/blockforge/generated/smartlook', 'SunMoon': b'cn/sunmoonblade', 'DeadDream': b'cn/blockforge/generated/deaddream',
 'SilverBlade': b'com/snowball/silvercideblade', 'RealTerminal': b'mods/mmr/terminal', 'GraeShield(ryjs)': b'com/ryjs/coremod',
}
def walk(z, prefix=''):
    for n in z.namelist():
        if n.endswith('.class'):
            yield prefix+n, z.read(n)
        elif n.endswith('.jar'):
            try:
                import io
                yield from walk(zipfile.ZipFile(io.BytesIO(z.read(n))), prefix+n+'!/')
            except Exception: pass
for dp, dn, fn in os.walk(sys.argv[1]):
    for f in sorted(fn):
        if not f.endswith('.jar'): continue
        z = zipfile.ZipFile(os.path.join(dp,f))
        refs = defaultdict(set); own=set(); strs=set()
        for n, b in walk(z):
            for k,p in PK.items():
                if n.split('!/')[-1].startswith(p.decode()): own.add(k)
        for n, b in walk(z):
            inner = n.split('!/')[-1]
            for k,p in PK.items():
                if k in own: continue
                if p in b or p.replace(b'/',b'.') in b: refs[k].add(inner)
            for s in re.findall(rb'[\x20-\x7e]{6,120}', b):
                if re.search(rb'(?i)(\.dll|\.jar|mods.|taskkill|cmd\.exe|powershell|http|\.minecraft|AppData|delete|halt|verify|hwid|-javaagent|jcmd)', s):
                    strs.add(s.decode('ascii','replace'))
        print('=== ', f, ' own=', sorted(own))
        for k,v in sorted(refs.items()): print(f'   -> {k}: {len(v)} classes e.g. {sorted(v)[:3]}')
        interesting=[s for s in strs if re.search(r'(?i)taskkill|cmd\.exe|powershell|mods.|AppData|hwid|verify|114\.|jcmd|-javaagent|\.minecraft', s)]
        for s in sorted(interesting)[:25]: print('     str:', s)
