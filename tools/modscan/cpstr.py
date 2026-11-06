import sys, zipfile, struct, re
def utf8s(b):
    if b[:4]!=b'\xca\xfe\xba\xbe': return ['<not a class>']
    n=struct.unpack('>H',b[8:10])[0]; i=10; out=[]; k=1
    while k<n:
        t=b[i]; i+=1
        if t==1:
            l=struct.unpack('>H',b[i:i+2])[0]; out.append(b[i+2:i+2+l].decode('utf8','replace')); i+=2+l
        elif t in(3,4,9,10,11,12,17,18): i+=4
        elif t in(5,6): i+=8; k+=1
        elif t in(7,8,16,19,20): i+=2
        elif t==15: i+=3
        else: break
        k+=1
    return out
jar=sys.argv[1]; z=zipfile.ZipFile(jar)
for c in sys.argv[2:]:
    print('##', c)
    try: ss=utf8s(z.read(c))
    except KeyError: print('  (missing)'); continue
    keep=[s for s in ss if len(s)>3 and not re.match(r'^[\(\[L]|^(Code|LineNumberTable|LocalVariableTable|StackMapTable|SourceFile|InnerClasses|Signature|Exceptions|this|<init>|<clinit>)$',s) and ' ' in s or re.search(r'(?i)\.dll|\.jar|mods|http|delete|exec|exit|halt|kill|cmd|hwid|verify|agent',s)]
    for s in keep[:40]: print('  ', s[:160])
