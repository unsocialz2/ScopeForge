"""Generate a fully offline dashboard with FICTIONAL example.org/.test data.
No network requests are made. No real Xiaomi hosts are depicted.
"""
from pathlib import Path
import sys
import html
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scopeforge import render_report, scoring, stamp, fingerprint, status_bucket

OUT=Path(__file__).resolve().parent
ROOTS=["example.org", "demo.test"]
items=[
("admin.console.example.org",200,"Control Center | Admin Dashboard", ["Next.js","React","nginx"],"high"),
("staging-api.example.org",200,"OpenAPI - Internal API Reference",["Express","React"],"high"),
("legacy.example.org",200,"Legacy Portal",["Apache","PHP"],"medium"),
("auth.example.org",401,"Single Sign-On",["nginx"],"high"),
("jenkins.dev.example.org",403,"Jenkins",["Jenkins"],"high"),
("docs.example.org",200,"Developer Documentation",["Next.js"],"medium"),
("shop.example.org",200,"Shop Collection",["WordPress","jQuery"],"low"),
("crm.demo.test",200,"Customer Relations",["React","Cloudflare"],"low"),
("login.demo.test",302,"Login Portal",["nginx"],"medium"),
("static.example.org",404,"",[],"low"),
("edge.demo.test",503,"Service Unavailable",["nginx"],"low"),
("expired.example.org",None,"",[],"low"),
("labs.demo.test",200,"Lab Experiment Workspace",["Vue"],"low"),
("backup.dev.example.org",200,"Storage Console",["Apache","PHP"],"medium"),
("graphql.example.org",200,"GraphQL Playground",["Express"],"medium"),
("preview.demo.test",200,"Release Preview",["Nuxt"],"low"),
]
for i,(host,status,title,tech_names,_) in enumerate(items):
    if status is None or status in (404,503):continue
    colors=[('#063f52','#0b2047','#5bffe2'),('#372354','#152643','#a89dfb'),('#2d3f59','#101e30','#f4b78a'),('#133e3e','#0a1c2f','#6ed6b0')]
    a,b,c=colors[i%4]
    domain_name=html.escape(host)
    heading=html.escape(title or host)
    panes=''.join(f'<rect x="{48+u*285}" y="218" width="250" height="118" rx="10" fill="#ffffff" opacity=".075"/><rect x="{67+u*285}" y="239" width="115" height="10" rx="5" fill="{c}" opacity=".65"/><rect x="{67+u*285}" y="260" width="164" height="6" rx="3" fill="#f8faff" opacity=".21"/><rect x="{67+u*285}" y="276" width="110" height="6" rx="3" fill="#f8faff" opacity=".12"/>' for u in range(3))
    svg=f'''<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="660" viewBox="0 0 1100 660"><defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient></defs><rect width="1100" height="660" fill="url(#bg)"/><rect width="1100" height="50" fill="#05111d" opacity=".45"/><circle cx="22" cy="25" r="6" fill="#fa929b"/><circle cx="43" cy="25" r="6" fill="#f6c37d"/><circle cx="64" cy="25" r="6" fill="#78d8b6"/><rect x="138" y="11" width="755" height="28" rx="7" fill="#071421" opacity=".68"/><text x="160" y="30" font-family="Arial,sans-serif" fill="#acbfcb" font-size="14">https://{domain_name}/</text><text x="48" y="110" font-family="Arial,sans-serif" font-weight="bold" fill="{c}" font-size="13" letter-spacing="5">FICTIONAL DEMONSTRATION</text><text x="48" y="163" font-family="Arial,sans-serif" font-weight="bold" fill="white" font-size="35">{heading}</text><text x="48" y="189" font-family="Arial,sans-serif" fill="#a1c1ce" font-size="17">Sample browser capture placeholder · no network requests</text>{panes}<rect x="48" y="375" width="819" height="225" rx="12" fill="#ffffff" opacity=".055"/><path d="M82 560 L170 510 L260 530 L340 451 L430 474 L520 424 L620 440 L750 401 L830 430" stroke="{c}" stroke-width="5" fill="none" opacity=".9"/><text x="78" y="416" font-family="Arial,sans-serif" fill="white" opacity=".6" font-size="14">OVERVIEW · SAMPLE DATA</text></svg>'''
    (OUT/'screenshots'/f'{host.replace(".","_")}.svg').write_text(svg,encoding='utf8')
rows=[]
for i,(host,status,title,tech_names,_) in enumerate(items):
    root='demo.test' if host.endswith('.demo.test') else 'example.org'
    headers={'Server':'nginx/1.24.0'} if 'nginx' in tech_names else {}
    tech=[{'name':tech,'version':'1.24.0' if tech=='nginx' else '','evidence':'Server header (demo)' if tech=='nginx' else 'Demonstration signature (fictional)'} for tech in tech_names]
    score,reasons,priority=scoring(host,status,title,tech,headers,'',False)
    # Tuned demo indicators only; no real-world finding claims.
    if status is None:score,reasons,priority=6,['Offline fictional host'], 'low'
    rows.append(dict(host=host,root=root,url=f'https://{host}/' if status else '',status=status,bucket=status_bucket(status),title=title,tech=tech,headers=headers,redirect='',external_redirect=False,error='',latency_ms=105+i*13,sources=['crtsh','subfinder'] if i%2 else ['otx','crtsh'],score=score,reasons=reasons,priority=priority,screen=f'screenshots/{host.replace(".","_")}.svg' if status is not None and status not in (404,503) else ''))
meta=dict(name='DEMO · Fictional Asset Workspace',version='1.0.0',generated=stamp(),scope_file='fictional_example_scope.csv',scope_roots=ROOTS,scope_wildcards=len(ROOTS),ignored_non_web=0,discovered=241,probed=len(rows),sources=['crtsh','otx','subfinder'],health={'crtsh':{'example.org':{'result':'ok','returned':112}},'otx':{'example.org':{'result':'ok','returned':28}},'subfinder':{'all':{'result':'ok','returned':160}}},screenshots=f'{len([r for r in rows if r["screen"]])} fake illustrative placeholders',passive_only=False,notice='FICTIONAL DEMO: hosts, screenshots and findings are illustrative, NOT live test results')
render_report(rows,meta,OUT)
# Friendly direct link with a name that distinguishes the fake demo.
(OUT/'README_DEMO.txt').write_text('FICTIONAL OFFLINE DEMO. No real hosts were probed. Open report.html in your browser.\n')
print(f'Wrote {OUT/"report.html"} ({len(rows)} fictional entries)')
