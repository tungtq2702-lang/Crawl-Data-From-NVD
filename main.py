import json
from urllib.request import urlopen


class _Response:
    def __init__(self, response):
        self._response = response

    def json(self):
        return json.loads(self._response.read().decode('utf-8'))


class _Requests:
    def get(self, url):
        return _Response(urlopen(url))


requests = _Requests()


def get_epss_score(CVE):
    url = 'https://api.first.org/data/v1/epss?cve=' + CVE
    
    response = requests.get(url)
    
    data = response.json()

    needed_data = data.get('data')
    
    if len(needed_data) > 0:
        epss_score = float(needed_data[0].get('epss'))
    else:
        return
    
    return epss_score
    
def is_in_kev(CVE):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + CVE
    
    response = requests.get(url)
    
    data = response.json()
    
    vul = data.get('vulnerabilities')
    
    if len(vul) > 0:
        cve = vul[0].get('cve')
    else:
        return
    
    if cve.get('cisaExploitAdd') != None:
        return True
    else:
        return False




test_CVE = 'CVE-2017-0203'

print(get_epss_score(test_CVE))
print(is_in_kev(test_CVE))



