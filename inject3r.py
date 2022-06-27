#!/usr/bin/python3
import sys
from utils import *
from detacter import *
from _class import Inject3r


# todo://每个模块的攻击代码 和 基本请求功能
# todo://header inject
atk_table = {
    # 'rce': [shellshock],
    # 'sqli': [sqli_error_based, sqli_bool_based, sqli_union_based, sqli_time_based,],
    # 'rce':  [rce_error_based, rce_time_based, shellshock],
    'ssti': [ssti,],
    # 'html': [],
    # 'nosqli': [],
    # 'xss':  [xss_common, xss_dom_based,], # 只发送payload不进行检测
}

args = argparser.parse()
data = {}
data['urls'] = []
if args.url:
    data['urls'].append(args.url)
elif args.urlList:
    with open(args.urlList, 'r') as f:
        for line in f.readlines():
            url = line.strip('\r').strip('\n')
            data['urls'].append(url)
elif args.requestFile:
    _data = request_file_extractor.extract(args.requestFile)
    data['urls'] = _data['urls']
else:
    # print_help()
    sys.exit(0)

data['method']  = _data['method'] if args.requestFile else args.method.upper()
data['data']    = _data['data'] if args.requestFile else args.data
data['data']    = param_extractor.data_extract(data['data'])
data['headers'], data['cookies'] = (_data['headers'], _data['cookies']) if args.requestFile else param_extractor.extract(args.headers, args.cookies)
data['proxies'] = handler.gen_proxies(args.proxy) if args.proxy else {}
data['json']    = args.json
data['params']  = args.params
data['threads'] = args.threads
data['outputFile'] = args.outputFile
data['verify']  = args.verify
attacks = [i for _ in args.attacks.split(',') for i in atk_table[_]] if args.attacks else [v for vs in atk_table.values() for v in vs]

if __name__ == '__main__':
    Inject3r(data, attacks).start()