import requests, copy


def single_request(data, pos, parameter, payload):
    data = copy.deepcopy(data)
    data[pos][parameter] += payload
    try:
        return requests.request(data['method'], data['url'], params=data['params'], data=data['data'], json=data['data'], cookies=data['cookies'], headers=data['headers'], proxies=data['proxies'], allow_redirects=False, verify=data['verify']) if data['json'] else requests.request(data['method'], data['url'], params=data['params'], data=data['data'], cookies=data['cookies'], headers=data['headers'], proxies=data['proxies'], allow_redirects=False, verify=data['verify'])
    except requests.exceptions.RequestException as e:
        print(f"[!] {e} at {single_request.__name__}")

def bool_request(data, pos, parameter, payload):
    data1 = copy.deepcopy(data)
    data0 = copy.deepcopy(data)
    data1[pos][parameter] += payload[1]
    data0[pos][parameter] += payload[0]
    try:
        r1 = requests.request(data1['method'], data1['url'], params=data1['params'], data=data['data'], json=data1['data'], cookies=data1['cookies'], headers=data1['headers'], proxies=data1['proxies'], allow_redirects=False, verify=data1['verify'])
        r0 = requests.request(data1['method'], data1['url'], params=data1['params'], data=data['data'], json=data0['data'], cookies=data0['cookies'], headers=data0['headers'], proxies=data0['proxies'], allow_redirects=False, verify=data0['verify'])
        return r1, r0
    except requests.exceptions.RequestException as e:
        print(f"[!] {e} at {bool_request.__name__}")