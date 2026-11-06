import sys, zipfile, re, os, struct, io, json
from collections import Counter

PAT = {
 'Unsafe': rb'sun/misc/Unsafe|jdk/internal/misc/Unsafe',
 'Instrumentation': rb'java/lang/instrument/Instrumentation',
 'ClassFileTransformer': rb'ClassFileTransformer',
 'ITransformationService': rb'cpw/mods/modlauncher/api/ITransformationService',
 'ILaunchPluginService': rb'ILaunchPluginService',
 'ASM': rb'org/objectweb/asm/ClassWriter',
 'defineClass/Hidden': rb'defineHiddenClass|defineAnonymousClass',
 'MethodHandles.Lookup IMPL': rb'IMPL_LOOKUP',
 'System.exit/halt': rb'java/lang/Runtime\x01\x00\x04halt|\x00\x04halt|java/lang/System.*exit',
 'Runtime.exec/ProcessBuilder': rb'java/lang/ProcessBuilder|\x00\x04exec\x01',
 'Network': rb'java/net/URL|java/net/Socket|HttpClient|https?://[\w./-]+',
 'JNI loadLibrary': rb'loadLibrary|java/lang/System\x01.{0,4}load',
 'Attach API': rb'com/sun/tools/attach|VirtualMachine\x01|jdk\.attach',
 'Thread stop/suspend': rb'\x00\x04stop\x01|\x00\x07suspend',
 'Reflection setAccessible': rb'setAccessible',
 'JVMTI/hotspot': rb'sun/jvm/hotspot|gHotSpot|JVMTI|jvmti',
 'Entity remove hooks': rb'net/minecraft/world/entity/Entity\$RemovalReason|setRemoved|discard',
 'File delete': rb'java/nio/file/Files.{0,40}delete|\x00\x06delete\x01',
 'Kill/mod-names': rb'(?i)secret|supersteve|arcanevortex|forever_love_sword|pig2mod|apphhzp|entityeraser|fading_black_sun|buer',
}

def scan(path):
    r = {'file': os.path.basename(path)}
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:
        r['error'] = str(e); return r
    names = z.namelist()
    r['classes'] = sum(n.endswith('.class') for n in names)
    r['natives'] = [n for n in names if re.search(r'\.(dll|so|dylib|d11)$', n, re.I)]
    r['nested_jars'] = [n for n in names if n.endswith('.jar')][:10]
    r['services'] = [n for n in names if n.startswith('META-INF/services/')]
    try:
        mf = z.read('META-INF/MANIFEST.MF').decode('utf8','replace')
        r['manifest'] = [l for l in mf.splitlines() if re.match(r'(Premain|Agent|Launcher-Agent|Can-|FMLModType|MixinConfigs|TweakClass|Automatic-Module|Main-Class)', l)]
    except KeyError: r['manifest'] = []
    r['mixin_targets'] = []
    for n in names:
        if re.search(r'mixins?.*\.json$', n, re.I) or n.endswith('.mixins.json'):
            try:
                j = json.loads(z.read(n))
                r['mixin_targets'].append((n, j.get('package'), len(j.get('mixins',[]))+len(j.get('client',[]))+len(j.get('server',[]))))
            except Exception: pass
    hits = Counter(); samples = {}
    big = []
    obf = 0
    for n in names:
        if not n.endswith('.class'): continue
        b = z.read(n)
        if b[:4] != b'\xca\xfe\xba\xbe': hits['NON-CAFEBABE class (encrypted?)'] += 1
        base = n.rsplit('/',1)[-1]
        if re.match(r'^[Il1O0]{4,}|^[a-z]{1,2}\.class$', base): obf += 1
        for k, p in PAT.items():
            m = re.search(p, b)
            if m:
                hits[k] += 1
                samples.setdefault(k, set())
                if len(samples[k]) < 4: samples[k].add(n)
        if k == 'Network':
            pass
    urls = set()
    for n in names:
        if n.endswith('.class'):
            for u in re.findall(rb'https?://[\x21-\x7e]{4,80}', z.read(n)):
                urls.add(u.decode('ascii','replace'))
    r['urls'] = sorted(urls)[:15]
    r['obf_like_classes'] = obf
    r['hits'] = dict(hits)
    r['samples'] = {k: sorted(v) for k,v in samples.items()}
    return r

out = []
for root in sys.argv[1:]:
    for dp, dn, fn in os.walk(root):
        for f in sorted(fn):
            if f.endswith('.jar'):
                out.append(scan(os.path.join(dp,f)))
for r in out:
    print('=== ', r['file'])
    for k in ('classes','natives','nested_jars','services','manifest','mixin_targets','obf_like_classes','urls','hits','samples','error'):
        if r.get(k): print(f'  {k}: {r[k]}')
