from pathlib import Path
import sys
import asyncio
import httpx
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scopeforge import Scope, normalize_host, record_source, extract_crt_names, status_bucket, fingerprint, scoring, probe_host, render_report

SCOPEFILE=Path(__file__).resolve().parents[1]/'inputs'/'xiaomi_scope.csv'

def test_scope_exactly_43_wildcards():
    scope=Scope.from_csv(SCOPEFILE)
    assert len(scope.wildcards)==43
    assert scope.includes('dev.mi.com')
    assert scope.includes('a.b.xiaomi.com')
    assert not scope.includes('mi.com')
    assert not scope.includes('evilmi.com')
    assert not scope.includes('mi.com.evil.example')
    assert not scope.includes('10.0.0.1')
    assert len(scope.ignored)==23

def test_discovery_scoped_and_crt_json():
    s=Scope(['mi.com'],[],[],[])
    out={}
    for name in extract_crt_names([{'name_value':'*.dev.mi.com\nhello.mi.com\nevil.example'}]):
        record_source(out,s,name,'crtsh')
    assert set(out)=={'dev.mi.com','hello.mi.com'}
    assert out['dev.mi.com']=={'crtsh'}

def test_status_and_technology():
    assert status_bucket(200)=='live'
    assert status_bucket(403)=='restricted'
    assert status_bucket(404)=='dead'
    assert status_bucket(500)=='server_error'
    assert status_bucket(None)=='unreachable'
    tech,title=fingerprint({'server':'nginx/1.24.0','x-powered-by':'PHP/8.2.1'}, '<html><title>Admin</title><meta name="generator" content="WordPress 6.4"></html>')
    assert title=='Admin'
    found={x['name']:x for x in tech}
    assert found['nginx']['version']=='1.24.0'
    assert found['PHP']['version']=='8.2.1'
    assert found['WordPress']['version']=='6.4'
    score,reasons,priority=scoring('admin.dev.mi.com',403,'Console',tech,{},'',False)
    assert priority=='high'

def test_http_redirects_never_follow_out_of_scope():
    requests=[]
    def handler(request):
        requests.append(str(request.url))
        return httpx.Response(302,headers={'Location':'https://external-login.example/'},text='')
    async def go():
        scope=Scope(['mi.com'],[],[],[])
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as cli:
            return await probe_host(cli,scope,'auth.mi.com',asyncio.Semaphore(2))
    result=asyncio.run(go())
    assert result['external_redirect']
    assert len(requests)==1
    assert result['bucket']=='redirect'

def test_https_404_http_fallback():
    def handler(req):
        if req.url.scheme=='https':return httpx.Response(404,text='not found')
        return httpx.Response(200,text='<title>Working</title>')
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as cli:
            return await probe_host(cli,Scope(['mi.com'],[],[],[]),'test.mi.com',asyncio.Semaphore(1))
    result=asyncio.run(go())
    assert result['status']==200 and result['title']=='Working'

def test_xss_safe_render(tmp_path):
    r=dict(host='evil.mi.com',root='mi.com',url='',status=200,bucket='live',priority='low',score=5,title='</script><script>alert(1)</script>',tech=[],sources=[],reasons=[],screen='')
    render_report([r],{'name':'test','scope_roots':['mi.com']},tmp_path)
    t=(tmp_path/'report.html').read_text()
    assert '</script><script>alert(1)</script>' not in t
    assert '\\u003c/script\\u003e' in t
    assert (tmp_path/'high_priority.txt').exists()
