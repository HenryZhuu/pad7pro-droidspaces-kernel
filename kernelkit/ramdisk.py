import hashlib,struct
import lz4.block

align=lambda n,p:(n+p-1)//p*p
digest=lambda b:hashlib.sha256(b).hexdigest()

def decompress(b):
    assert b[:4]==bytes.fromhex('02214c18')
    pos=4; chunks=[]
    while pos+4<=len(b):
        size=struct.unpack_from('<I',b,pos)[0];pos+=4
        if size==0:break
        assert pos+size<=len(b)
        chunks.append(lz4.block.decompress(b[pos:pos+size],uncompressed_size=8*1024*1024));pos+=size
    assert not any(b[pos:])
    return b''.join(chunks)

def compress(b):
    out=bytearray(bytes.fromhex('02214c18'))
    for pos in range(0,len(b),8*1024*1024):
        block=lz4.block.compress(b[pos:pos+8*1024*1024],mode='high_compression',compression=9,store_size=False)
        out+=struct.pack('<I',len(block))+block
    assert decompress(out)==b
    return bytes(out)

def entries(b):
    pos=0
    while pos+110<=len(b):
        assert b[pos:pos+6] in (b'070701',b'070702'),(pos,b[pos:pos+6])
        start=pos;header=b[pos:pos+110]
        fields=[int(header[6+i*8:14+i*8],16) for i in range(13)]
        size,namesize=fields[6],fields[11]
        name=b[pos+110:pos+110+namesize-1].decode()
        data_start=align(pos+110+namesize,4);end=align(data_start+size,4)
        yield dict(name=name,fields=fields,header=header,prefix=b[pos+110:data_start],content=b[data_start:data_start+size],raw=b[start:end],end=end)
        pos=end
        if name=='TRAILER!!!':
            assert not any(b[pos:]),'Unexpected appended archive'
            return

def rewrite(b,replacements):
    out=bytearray();changed=[]
    for e in entries(b):
        if e['name'] in replacements:
            v=replacements[e['name']];f=e['fields'].copy();f[6]=len(v)
            if e['header'][:6]==b'070702':f[12]=sum(v)&0xffffffff
            out+=e['header'][:6]+''.join(f'{x:08x}' for x in f).encode()+e['prefix']+v+b'\0'*((-len(v))%4)
            changed.append(e['name'])
        else:out+=e['raw']
    out+=b[e['end']:]
    old=list(entries(b));new=list(entries(out));assert len(old)==len(new)
    for a,c in zip(old,new):
        assert a['name']==c['name']
        assert a['prefix']==c['prefix']
        assert all(a['fields'][i]==c['fields'][i] for i in range(13) if i not in (6,12))
        assert c['content']==replacements.get(a['name'],a['content'])
    return bytes(out),changed

def parts(b):
    assert b[:8]==b'VNDRBOOT' and struct.unpack_from('<I',b,8)[0]==4
    page=struct.unpack_from('<I',b,12)[0];size=struct.unpack_from('<I',b,24)[0]
    dtb_size=struct.unpack_from('<I',b,2100)[0]
    ts,count,es,bs=struct.unpack_from('<IIII',b,2112)
    dtboff=page+align(size,page);toff=dtboff+align(dtb_size,page);boff=toff+align(ts,page)
    table=b[toff:toff+ts];frags=[]
    for i in range(count):
        sz,off=struct.unpack_from('<II',table,i*es)
        frags.append(b[page+off:page+off+sz])
    return page,table,es,frags,b[dtboff:dtboff+dtb_size],b[boff:boff+bs]

def repack(original,replacements):
    page,table,es,frags,dtb,bc=parts(original)
    table=bytearray(table);ramdisk=bytearray();changed=[];records=[]
    for i,frag in enumerate(frags):
        if frag:
            raw=decompress(frag);new,names=rewrite(raw,replacements)
            newfrag=compress(new) if names else frag
            changed+=names
            records.append(dict(fragment=i,files=len(list(entries(raw))),modified=names))
        else:newfrag=frag
        struct.pack_into('<II',table,i*es,len(newfrag),len(ramdisk));ramdisk+=newfrag
    assert sorted(changed)==sorted(replacements)
    header=bytearray(original[:page]);struct.pack_into('<I',header,24,len(ramdisk))
    out=bytes(header)
    for data in (ramdisk,dtb,table,bc):out+=bytes(data)+b'\0'*((-len(data))%page)
    np,nt,ne,nf,nd,nb=parts(out)
    assert nd==dtb and nb==bc and np==page and ne==es
    for i in range(len(frags)):assert nt[i*es+8:(i+1)*es]==table[i*es+8:(i+1)*es]
    return out,records
