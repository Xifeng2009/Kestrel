import re


def extract(requestFile):
    in2body = False
    data, _data = {}, []
    with open(requestFile, 'r') as f:
        for line in f.readlines():
            _data.append(line.strip('\r').strip('\n'))
    data['method'], data['path'], _ = _data[0].split(' ')
    _data = _data[1:]
    data['headers'] = {}
    for i in _data:
        if i == '':
            in2body = True
        if not in2body:
            if match := re.match(r'Cookie: (?P<cookies>.*)', i):
                data['cookies'] = {}
                for _ in match.group('cookies').replace(' ', '').split(';'):
                    k, v = _.split('=')
                    data['cookies'][k] = v
            else:
                match = re.match(r'(?P<key>[A-Za-z0-9-]+): (?P<value>.*)', i)
                data['headers'][match.group('key')] = match.group('value')
        else:
            data['data'] = i

    # todo:// https and http
    data['urls'] = [f"https://{data['headers']['Host']}{data['path']}"]

    return data

# data = extract('r.txt')
# for k, v in data.items():
#     print(k, v)