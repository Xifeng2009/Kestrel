#!/usr/bin/python3
import sys, requests, time, re, random, string, copy, argparse, json
from threading import Thread, Lock, Semaphore
from colorama import init, Fore, Back, Style
init()

R = random.randint(1000000, 9999999)
ERROR_BASED_SQL = ('\'', '"', '(', ')')
BOOLEAN_BASED_SQL = [{True: i % (R, R), False: i % (R, R-1)} for i in ("' AND %d=%d-- -", "' AND %d=%d#", "' OR NOT (%d>%d)-- -", "' OR NOT (%d>%d)#", ' AND %d=%d-- -', ' AND %d=%d#', ' OR NOT (%d>%d)-- -', ' OR NOT (%d>%d)#', '" AND %d=%d-- -', '" AND %d=%d#', '" OR NOT (%d>%d)-- -', '" OR NOT (%d>%d)#', ') AND %d=%d-- -', ') AND %d=%d#', ') OR NOT (%d>%d)-- -', ') OR NOT (%d>%d)#', "') AND %d=%d-- -", "') AND %d=%d#", "') OR NOT (%d>%d)-- -", "') OR NOT (%d>%d)#", '") AND %d=%d-- -', '") AND %d=%d#', '") OR NOT (%d>%d)-- -', '") OR NOT (%d>%d)#')]
TIME_BASED_SQL  = ("' AND (SELECT sleep(10))-- -", "' AND (SELECT sleep(10))#", "' ||pg_sleep(10)-- -", "' ||pg_sleep(10)#", ' AND (SELECT sleep(10))-- -', ' AND (SELECT sleep(10))#', ' ||pg_sleep(10)-- -', ' ||pg_sleep(10)#', '" AND (SELECT sleep(10))-- -', '" AND (SELECT sleep(10))#', '" ||pg_sleep(10)-- -', '" ||pg_sleep(10)#', ') AND (SELECT sleep(10))-- -', ') AND (SELECT sleep(10))#', ') ||pg_sleep(10)-- -', ') ||pg_sleep(10)#', "') AND (SELECT sleep(10))-- -", "') AND (SELECT sleep(10))#", "') ||pg_sleep(10)-- -", "') ||pg_sleep(10)#", '") AND (SELECT sleep(10))-- -', '") AND (SELECT sleep(10))#', '") ||pg_sleep(10)-- -', '") ||pg_sleep(10)#')
ERROR_BASED_RCE = [i % (R, R) for i in (';expr %d + %d', ';%d + %d', '&&expr %d + %d', '&&%d + %d', '|expr %d + %d', '|%d + %d', '||expr %d + %d', '||%d + %d', '`expr %d + %d`', '`%d + %d`', '$((expr %d + %d))', '$((%d + %d))', )]
ERROR_BASED_RCE+= [i % (R, R) for i in (';eval("%d+%d")', '&&eval("%d+%d")', '||eval("%d+%d")', '|eval("%d+%d")', )]
TIME_BASED_RCE  = ["||sleep 10||", "||ping -c 10 127.0.0.1||"]
SSTI = [i % (R, R) for i in ('${%d*%d}', '{{%d*%d}}', '{{%d*\'%d\'}}', '<%%= %d*%d %%>')]
SCAN_TYPES = ['ERROR_BASED_SQL', 'BOOLEAN_BASED_SQL', 'TIME_BASED_SQL', 'ERROR_BASED_RCE', 'TIME_BASED_RCE', 'SSTI']

def parser():
    parser = argparse.ArgumentParser(prog='K3sTre1', conflict_handler='resolve')
    parser.add_argument('-u', dest='url', type=str, help='REQUEST URL')
    parser.add_argument('-b', dest='bulkFile', type=str, help='SCAN URLS IN TEXT FILE, SHOULD STARTS WITH http:// OR https://') # todo://
    parser.add_argument('-r', dest='requestFile', type=str, help='SCAN FROM REQUESTFILE')# todo://
    parser.add_argument('-m', dest='methods', type=str, help='METHODS WILL BE TESTED (e.g. GET,POST,DELETE,PUT,PATCH)')# todo://
    parser.add_argument('-d', dest='data', type=str, default='', help='POST DATA')# todo://
    parser.add_argument('-j', dest='json', type=str, default='', help='POST JSON')# todo://
    parser.add_argument('-H', dest='headers', type=str, default='', help='REQUEST HEADERS (e.g. User-Agent: _______\nReferer: ________')# todo://
    parser.add_argument('-c', dest='cookies', type=str, default='', help='REQUEST COOKIES')# todo://
    parser.add_argument('-s', dest='skip', type=str, help='PARAMETERS DONT WANNA BE TESTED (e.g. csrf,session)')# todo://
    parser.add_argument('-p', dest='param', type=str, help='PARAMETERS WILL ONLY BE TESTED (e.g. id,name)')# todo://
    parser.add_argument('--tech', type=str, help='TECHNIQUES WILL ONLY BE TESTED (e.g. sqli,rce,ssti,xss,)')# todo://
    parser.add_argument('-x', dest='proxies', type=str, help='PROXY SERVER (e.g. http://127.0.0.1:8080')# todo://
    parser.add_argument('--nonstop', action='store_true', help='SCAN UNTIL THE END')        # todo://
    parser.add_argument('--random-agent', action='store_true', help='ENABLE RANDOM AGENT')  # todo://
    parser.add_argument('-v', dest='verbose', type=int, choices=(1,2,3), default=1, help='VERBOSE LEVEL OF OUTPUT')             # todo://
    parser.add_argument('-t', dest='threads', default=10, type=int, help='THREADS DEFAULT 10')            # todo://
    parser.add_argument('-o', dest='output', type=str, help='OUTPUT FILENAME')                     # todo://
    parser.add_argument('-h', dest='help', action='store_true', help='PRINT THIS')
    return parser

USAGE = '''
python3 k3sTrel.py -u <url>
python3 k3sTrel.py -u <url> -d <data> -c <cookies> -H <headers>
python3 k3sTrel.py -u <url> -j <json> -s csrf,session
python3 k3sTrel.py -u <url> -d <data> -p id,name
python3 k3sTrel.py -u <url> --tech sqli
python3 k3sTrel.py -b <urlsFile>
python3 k3sTrel.py -r <requestFile> -s csrf,session
'''

class K3sTre1:
    def __init__(self, cookies='', headers='', proxies='', rfile=''):
        self.cookies = {i.split('=')[0]:i.split('=')[1] for i in cookies.replace(' ','').split(';')} if cookies else {}
        self.headers = {i.split(':')[0]:i.split(':')[1] for i in headers.replace(' ','').split('\\n')} if headers else {}
        self.proxies = {} if proxies else {}
        self.rfile   = rfile
        self.vulnerable = False

    @staticmethod
    def print_ok(msg=''):
        for i in range(3):
            time.sleep(0.1)
            print('.', end='')
        print("OK" if not msg else msg)

    def print_info(self, url, k, v, msg):
        self.lock.acquire()
        print(f"[+] :::{Fore.RED+msg+Style.RESET_ALL}:::{Fore.GREEN+k+Style.RESET_ALL}:::{Fore.GREEN+v+Style.RESET_ALL}:::")
        if output:
            with open(output, 'a') as f:
                f.write(f":::{url}:::{msg}:::{k}:::{v}:::\n")
        self.lock.release()

    def build_session(self):
        print("[*] Building Request Session", end='')
        self.s = requests.Session()
        self.s.cookies.update(self.cookies)
        self.s.headers.update(self.headers)
        self.s.proxies.update(self.proxies)
        self.print_ok()

    def build_threading_lock(self):
        print("[*] Building Lock", end='')
        self.lock = Lock()
        self.print_ok()
        print("[*] Building Semaphore", end='')
        self.sem  = Semaphore(threads)
        self.print_ok()

    def is_host_alive(self, url):
        print("[*] Testing Host Alive", end='')
        url = re.match(r'(?P<base>https?://[a-zA-Z0-9-.]*)', url).group('base')
        try:
            r = self.s.get(url, timeout=30)
            self.print_ok(msg=r.status_code)
            return False if r.status_code != 200 else True
        except requests.exceptions.ReadTimeout:
            self.print_ok(msg='False')
            return False
        except KeyboardInterrupt:
            self.print_ok(msg='CTRL-C')

    def find_param_from_url_or_data(self, url_or_data, json=None):
        data = []
        self.param_base = {}
        if not json:
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url_or_data):
                data.append(('url', match.group('parameter'), match.group('value')))
                self.param_base[match.group('parameter')] = match.group('value')
        else:
            for k, v in json.items():
                data.append(('url', k, v))
                self.param_base[k] = v
        if self.cookies:
            for k, v in self.cookies.items():
                data.append(('cki', k, v))
        if self.headers:
            for k, v in self.headers.items():
                data.append(('hdr', k, v))
        return data

    def hunt(self):
        1




ap = parser()
args = ap.parse_args()

if args.bulkfile:
    with open(args.bulkfile, 'r') as f:
        for line in f.readlines():
            urls.append(line.strip('\r').strip('\n'))
data = args.data
jata = json.loads(args.json) if args.json else {}
is_post = True if (data or json) else False
proxies = {'http': args.proxies, 'https': args.proxies}
threads = args.threads
output  = args.output
nonstop = args.nonstop

urls = []
if args.help:
    ap.print_help()
    print(USAGE)
elif args.url or args.bulkFile:
    if args.url:
        urls.append(args.url)
    else:
        with open(args.bulkFile, 'r') as f:
            for line in f.readlines():
                urls.append(line.strip('\r').strip('\n'))
    k = K3sTre1(args.cookies, args.headers, proxies)
    k.hunt()
elif args.requestFile:
    k = K3sTre1(rfile=args.requestFile)
    k.hunt()
else:
    print('ERROR')