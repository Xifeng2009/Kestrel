import argparse


def parse():
    p = argparse.ArgumentParser(conflict_handler='resolve', prog='kestrel', description='fast vuln scanner')
    p.add_argument('-u', dest='url', type=str)
    p.add_argument('-m', dest='method', type=str, default='GET')
    p.add_argument('-d', dest='data', type=str, default='{}')
    p.add_argument('--json', dest='json', action='store_true')
    p.add_argument('-l', dest='urlList', type=str)
    p.add_argument('-r', dest='requestFile', type=str)
    p.add_argument('-x', dest='attacks', default='', type=str) # -x sqli,xss,rce,ssti
    p.add_argument('--level', dest='level', type=int, default=1)
    p.add_argument('-p', dest='params') # specify params for test
    p.add_argument('-H', dest='headers', type=str)
    p.add_argument('-c', dest='cookies', type=str)
    p.add_argument('--proxy', dest='proxy', type=str)
    p.add_argument('--threads', dest='threads', default=8, type=int)
    p.add_argument('-k', dest='verify', action='store_false', default=True)
    p.add_argument('-o', dest='outputFile', type=str)
    p.add_argument('-h', dest='help', action='store_true')

    return p.parse_args()