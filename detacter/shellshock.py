import re, itertools, random
from utils.requester import *
from threading import Thread, Semaphore
from config import *


# tech = "Shellshock"
# prefixs = (";", "|", "||", "&&")
# cmds    = ("expr %d + %d", "%d + %d",)
# payloads = []
# for pre, cmd in itertools.product(prefixs, cmds):
#     payloads.append(f"{pre}{cmd}" % (R1, R2))
# embeds = ("$({})", "`{}`")
# for embed, cmd in itertools.product(embeds, cmds):
#     payloads.append(embed.format(cmd))
#
# def exec(data):
#     for pos, payload in itertools.product(POSITIONS, payloads):
#         for parameter in data[pos].keys():
#             r = single_request(data, pos, parameter, payload)
#             print(r.text)
            # if re.search(str(R), r.text):
            #     print(f"■■■{tech}■■■{pos}■■■{parameter}■■■{payload}■■■")
            #     return True
#