import re, itertools, random, time
from utils.requester import *
from threading import Thread, Semaphore
from config import *


R1 = random.randint(100, 999)
R2 = random.randint(100, 999)
R  = str(R1 * R2)
tech = "Server Side Template Injection"
payloads = (i % (R1, R2)for i in ("}}{{%d*%d}}", "${%d*%d}", "%%><%%= %d*%d %%>"))

def exec(data):
    for pos, payload in itertools.product(POSITIONS, payloads):
        for parameter in data[pos].keys():
            r = single_request(data, pos, parameter, payload)
            if re.search(R, r.text):
                print(f"■■■{tech}■■■{pos}■■■{parameter}■■■{payload}■■■")
                return True