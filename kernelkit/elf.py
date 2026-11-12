from pathlib import Path
import hashlib,struct,mmap
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def elf(b):
    assert b[:6]==b'\x7fELF\x02\x01'
    off=struct.unpack_from('<Q',b,40)[0];size,count,si=struct.unpack_from('<HHH',b,58)
    secs=[struct.unpack_from('<IIQQQQIIQQ',b,off+i*size) for i in range(count)]
    s=secs[si];strings=b[s[4]:s[4]+s[5]]
    return {strings[s[0]:].split(b'\0',1)[0].decode():s for s in secs},secs

def module(b,path):
    sections,secs=elf(b);versions={};exports=[];imports=[];info={}
    for name,s in sections.items():
        data=b[s[4]:s[4]+s[5]]
        if name=='__versions':
            assert len(data)%64==0
            for off in range(0,len(data),64):versions[data[off+8:off+64].split(b'\0',1)[0].decode()]=struct.unpack_from('<Q',data,off)[0]
        if name=='.modinfo':
            for item in data.split(b'\0'):
                if b'=' in item:
                    k,v=item.decode().split('=',1);info.setdefault(k,[]).append(v)
        if name=='.symtab':
            st=secs[s[6]];strings=b[st[4]:st[4]+st[5]]
            for off in range(0,len(data),s[9]):
                noff=struct.unpack_from('<I',data,off)[0];sym=strings[noff:].split(b'\0',1)[0]
                if sym.startswith(b'__ksymtab_'):exports.append(sym[10:].decode())
                bind=data[off+4]>>4;shndx=struct.unpack_from('<H',data,off+6)[0]
                if sym and bind==1 and shndx==0:imports.append(sym.decode())
    return dict(path=path,versions=versions,exports=exports,imports=imports,info=info,sha256=hashlib.sha256(b).hexdigest())

def der(b,pos=0):
    start=pos;tag=b[pos];n=b[pos+1];pos+=2
    if n&128:
        count=n&127;n=int.from_bytes(b[pos:pos+count],'big');pos+=count
    assert pos+n<=len(b)
    return tag,b[pos:pos+n],b[start:pos+n],pos+n

def children(b):
    out=[];pos=0
    while pos<len(b):
        tag,value,raw,pos=der(b,pos);out.append((tag,value,raw))
    return out

def certificate_list(vmlinux):
    with vmlinux.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as b:
        sections,secs=elf(b);s=sections['.symtab'];st=secs[s[6]];strings=b[st[4]:st[4]+st[5]];found={}
        for off in range(s[4],s[4]+s[5],s[9]):
            noff,info,other,shndx,value,size=struct.unpack_from('<IBBHQQ',b,off)
            name=strings[noff:strings.find(b'\0',noff)].decode()
            if name in ('system_certificate_list','system_certificate_list_size'):
                sec=secs[shndx];found[name]=sec[4]+value-sec[3]
        n=struct.unpack_from('<Q',b,found['system_certificate_list_size'])[0]
        data=b[found['system_certificate_list']:found['system_certificate_list']+n]
    certs=[];pos=0
    while pos<len(data):
        _,_,raw,pos=der(data,pos);certs.append(x509.load_der_x509_certificate(raw))
    return certs,data

def image_certificate_list(image,system_map):
    syms={}
    for line in system_map.read_text().splitlines():
        f=line.split()
        if len(f)==3 and f[2] in ('_text','system_certificate_list','system_certificate_list_size'):syms[f[2]]=int(f[0],16)
    b=image.read_bytes();base=syms['_text'];off=syms['system_certificate_list']-base
    n=struct.unpack_from('<Q',b,syms['system_certificate_list_size']-base)[0]
    assert 0<n<100000 and 0<=off<len(b)
    data=b[off:off+n];certs=[];pos=0
    while pos<len(data):
        _,_,raw,pos=der(data,pos);certs.append(x509.load_der_x509_certificate(raw))
    return certs,data

def verify_signature(b,certs):
    magic=b'~Module signature appended~\n'
    if not b.endswith(magic):return 'unsigned'
    end=len(b)-len(magic);meta=b[end-12:end];siglen=int.from_bytes(meta[8:12],'big')
    assert meta[2]==2 and meta[3]==0 and meta[4]==0
    content=b[:end-12-siglen];sig=b[end-12-siglen:end-12]
    sd=children(children(children(sig)[0][1])[1][1])[0]
    signerinfos=children(sd[1])[-1];assert signerinfos[0]==0x31
    signer=children(children(signerinfos[1])[0][1]);sid=children(signer[1][1])
    serial=int.from_bytes(sid[1][1],'big');cert=next((c for c in certs if c.serial_number==serial),None)
    if cert is None:return 'unrecognized-signer:'+hex(serial)
    oid=children(signer[2][1])[0][1].hex()
    alg={'2b0e03021a':hashes.SHA1,'608648016503040201':hashes.SHA256,'608648016503040202':hashes.SHA384,'608648016503040203':hashes.SHA512}[oid]()
    assert signer[3][0]==0x30,'Unexpected authenticated attributes; requires separate verification'
    assert signer[4][0]==4
    cert.public_key().verify(signer[4][1],content,padding.PKCS1v15(),alg)
    return cert.fingerprint(hashes.SHA256()).hex()
