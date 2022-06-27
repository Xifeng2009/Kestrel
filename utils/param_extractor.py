import re, json


def url_extract(url):
    params = {}
    for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url):
        params[match.group('parameter')] = match.group('value')
    return params

def extract(headers=None, cookies=None):
    _c = {i.split('=')[0]: i.split('=')[1] for i in cookies.replace(' ', '').split(';')} if cookies else {}
    _h = {i.split(':')[0]: i.split(':')[1] for i in headers.replace(' ', '').split('\\n')} if headers else {}
    return _h, _c

def data_extract(data):
    try:
        return json.loads(data)
    except json.decoder.JSONDecodeError:
        return {i.split('=')[0]:i.split('=')[1] for i in data.split('&')}