#!/usr/bin/env python3
import glob
import json
import os
import shutil
import subprocess
import sys
import time

"""
Total: 2096.0 MB
   234.0  52.6%  52.6%    444.6 100.0% Connection::BuildConnVal
    78.0  17.6%  70.2%     78.0  17.6% safe_malloc (inline)
    37.5   8.4%  78.6%     61.5  13.8% analyzer::tcp::TCP_Analyzer::UpdateConnVal
    31.0   7.0%  85.6%     31.0   7.0% TableVal::Init
    25.5   5.7%  91.3%     25.5   5.7% analyzer::conn_size::ConnSize_Analyzer::UpdateConnVal
    14.5   3.3%  94.6%     14.5   3.3% BroString::Set@1e0900
    10.0   2.2%  96.9%     10.0   2.2% AddrVal::AddrVal
     8.0   1.8%  98.7%     86.0  19.4% RecordVal::RecordVal
     3.0   0.7%  99.3%     17.5   3.9% StringVal::StringVal
     2.5   0.6%  99.9%      2.5   0.6% analyzer::udp::UDP_Analyzer::UpdateEndpointVal
     0.5   0.1% 100.0%      0.5   0.1% analyzer::icmp::ICMP_Analyzer::UpdateEndpointVal
     0.0   0.0% 100.0%     78.0  17.6% BaseList::BaseList
     0.0   0.0% 100.0%      6.0   1.3% BifEvent::generate_ssl_encrypted_data
     0.0   0.0% 100.0%      0.5   0.1% BroFunc::Call
     0.0   0.0% 100.0%      0.5   0.1% BuiltinFunc::Call
     0.0   0.0% 100.0%      0.5   0.1% CallExpr::Eval
     0.0   0.0% 100.0%     66.0  14.8% Connection::DeleteTimer
     0.0   0.0% 100.0%    434.1  97.6% Connection::Event
     0.0   0.0% 100.0%      7.5   1.7% Connection::InactivityTimer
"""

def parse(prof):
    lines = [l.rstrip() for l in prof.splitlines()]
    total_mb = float(lines[0].split()[1])
    locations = []
    profile = {"total_mb": total_mb, "locations": locations}
    for line in lines[1:]:
        line = line.replace("% ", " ")
        a, b, c, d, e, func = line.split(None, 5)
        locations.append({
            'func': func,
            'direct_mb': float(a),
            'direct_pct': float(b),
            'direct_pct_cumm': float(c),
            'callees_mb': float(d),
            'callees_pct': float(e),
        })

    return profile

def maybe_int(s):
    try:
        return int(s)
    except ValueError:
        return s

def sort_key(s):
    return [maybe_int(w) for w in s.split(".")]

def run_jeprof(f):
    zeek_bin = shutil.which("zeek")
    out = subprocess.check_output(["jeprof", zeek_bin, f, "--text"])
    parsed = parse(out.decode())
    return parsed

def process_once(spool_dir):
    processed = 0
    files = glob.glob(os.path.join(spool_dir, "*", "jeprof.out*"))
    for f in sorted(files, key=sort_key):
        print(f)
        res = run_jeprof(f)
        with open("prof.log.txt", 'a') as l:
            l.write(json.dumps(res) + "\n")
        os.unlink(f)
        processed += 1
    return processed

def process(spool_dir):
    while True:
        processed = process_once(spool_dir)
        if not processed:
            time.sleep(60)
    return 0

if __name__ == "__main__":
    spool_dir = sys.argv[1]
    sys.exit(process(spool_dir))
