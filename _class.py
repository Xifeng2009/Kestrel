'''
data = {
    urls
    method
    data
      json
    geaders
    cookies
    attacks
    proxies
    threads
    outputFile
}
'''
import itertools
from utils.param_extractor import url_extract

class Inject3r:
    def __init__(self, data, attacks):
        self.data = data
        self.attacks = attacks

    def output(self):
        return

    def start(self):
        for url, atk in itertools.product(self.data['urls'], self.attacks):
            self.data['params'] = url_extract(url)
            self.data['url'] = url.split('?')[0]
            vuln = atk.exec(self.data)
            if vuln:
                break