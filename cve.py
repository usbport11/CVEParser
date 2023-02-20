#!/usr/bin/python3

import requests
import re
from bs4 import BeautifulSoup
import psycopg2
from psycopg2 import Error
import time

def getTopCVEList_cvetrends():
  link = 'https://cvetrends.com/api/cves/24hrs'
  r = requests.get(link, proxies=proxies)
  soup = BeautifulSoup(r.text, "lxml")
  regex = re.findall(r'"cve": "CVE-\d{4}-\d{4,8}"', soup.get_text())
  topCVEList = []
  for item in regex:
    topCVEList.append(re.search(r'CVE-\d{4}-\d{4,8}', item).group())
  return topCVEList

def getTopCVEList_opencve():
  url1 = 'https://www.opencve.io/login/'
  url2 = 'https://www.opencve.io/login'
  csrf_token = ''
  s = requests.Session()
  response = s.get(url1, proxies=proxies)
  soup = BeautifulSoup(response.text, 'lxml')

  # Get CSRF
  for a in soup.find_all('meta'):
    if 'name' in a.attrs:
      if a.attrs['name'] == 'csrf-token':
        csrf_token = a.attrs['content']

  # Authentication
  s.post(
    url2,
    data={
      'username': 'someusername',
      'password': 'somepassword',
      'csrf_token': csrf_token,
    },
    headers={'referer': 'https://www.opencve.io/login'},
    verify=False,
    proxies=proxies
  )
  # Get new CVE
  cve_line = []
  for page_num in range(1, 20):
    pagination = f'https://www.opencve.io/?page={page_num}'
    resp = s.get(pagination, proxies=proxies)
    parse = BeautifulSoup(resp.text, 'lxml')
    for cve in parse.find_all('h3', class_='timeline-header'):
      index = cve.text.find('has changed')
      if index == -1:
        cve_line.append(cve.text.replace(' is a new CVE', ''))

  cve_line_no_replic = []
  for item in cve_line:
    if item not in cve_line_no_replic:
      cve_line_no_replic.append(item[:-1])
  return cve_line_no_replic

def getCVEDataSelf(cve):
  sql = "select count(*) from list where name = '" + cve + "'"
  count = 0
  try:
    conn = psycopg2.connect(dbname='cve', user='cve', password='cve', host='localhost')
    cursor = conn.cursor()
    cursor.execute(sql, cve)
    count = cursor.fetchone()[0]
    conn.commit()
  except (Exception, Error) as error:
    print(error)
  finally:
    cursor.close()

  if count >= 1:
   print("%s alredy added to database"%(cve))
   return

  url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
  try:
    res = requests.get(url, proxies=proxies).json()
  except:
    print("Error while request to cve base")
    return

  if res['totalResults'] <= 0:
    print("Can't find %s"%(cve))
    return
  requestDate = res['timestamp']
  cve = res['vulnerabilities'][0]['cve']
  vulnStatus = cve['vulnStatus']
  name = cve['id']
  published = cve['published']
  published = published[0:10] + " " + published[11:19]
  description = cve['descriptions'][0]['value']

  metrics = cve['metrics']
  if len(metrics) >= 1:
    if 'cvssMetricV31' in metrics:
      metrics = metrics['cvssMetricV31'][0]['cvssData']
    elif 'cvssMetricV30' in metrics:
      metrics = metrics['cvssMetricV30'][0]['cvssData']
    attackVector = metrics['attackVector']
    attackComplexity = metrics['attackComplexity']
    baseScore = metrics['baseScore']
    baseSeverity = metrics['baseSeverity']
  else:
    attackVector = "unknown"
    attackComplexity = "unknown"
    baseScore = 0.0
    baseSeverity = "unknown"

  dbname = 'cve'
  username = 'cve'
  password = 'cve'
  host = 'localhost'

  sql = """insert into list (name, vuln_status, published, description, attack_vector, attack_complexity, base_score, base_severity)
    values (%s, %s, %s, %s, %s, %s, %s, %s)"""
  values = (name, vulnStatus, published, description, attackVector, attackComplexity, baseScore, baseSeverity)

  try:
    conn = psycopg2.connect(dbname='cve', user='cve', password='cve', host='localhost')
    cursor = conn.cursor()
    cursor.execute(sql, values)
    conn.commit()
  except (Exception, Error) as error:
    print(error)
  finally:
    cursor.close()
    print("%s add to database"%(name))
    
http_proxy  = "http://192.168.1.1:8080"

proxies = {
  "http"  : http_proxy,
  "https" : http_proxy
}

CVEList = getTopCVEList_cvetrends()
for cve in CVEList:
  print(cve + " processing ...")
  getCVEDataSelf(cve)
  #if future need sleep only after get new CVE data
  time.sleep(5)
