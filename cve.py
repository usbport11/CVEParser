#!/usr/bin/python3

import requests
import re
from bs4 import BeautifulSoup
import psycopg2
from psycopg2 import Error
import time
import json

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
      'username': 'user',
      'password': 'pass',
      'csrf_token': csrf_token,
    },
    headers={'referer': 'https://www.opencve.io/login'},
    verify=False,
    proxies=proxies
  )

  # Get new CVE
  cve_line = []
  for page_num in range(1, 10):
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

def getLastCVE_circl():
  link = 'https://cve.circl.lu/api/last'
  r = requests.get(link, proxies=proxies)
  data = r.json()
  cves = []
  for item in data:
    cves.append(item['id'])
  return cves

def getCitrixCVEList():
  list = []
  link = "https://support.citrix.com/knowledge-center/search/#/All%20Products?ct=Security%20Bulletins&searchText=&sortBy=Created%20date&pageIndex=1"
  r = requests.get(link, proxies=proxies)
  soup = BeautifulSoup(r.text, "lxml")
  ul = soup.find('ul')
  lis = ul.find_all('li')
  i = 0
  limit = 3
  for li in lis:
    print(li.find('a', href=True)['href'])
    i = i + 1
    if i >= limit:
      break

def getCitrixCVE(link):
  r = requests.get(link, proxies=proxies)
  soup = BeautifulSoup(r.text, "lxml")
  severity = soup.select_one('div.article-meta-info > span.category > span.severity').text
  created = soup.find("meta", attrs={"name":"creationDate"})['content']
  div = soup.find('div', {'data-swapid':'SecurityBulletinVulnerabilitiesList'})
  table = div.find('table')
  table_head = table.find('thead')
  row = table_head.find('tr')
  cols = row.find_all('th')
  descrPos = 0
  scorePos = 0
  i = 0
  for col in cols:
    if col.text == 'Description':
      descrPos = i
    if col.text == 'CVSS':
      scorePos = i
    i = i + 1
  table_body = table.find('tbody')
  rows = table_body.find_all('tr')
  for row in rows:
    cols = row.find_all('td')
    id = cols[0].text
    descr = cols[descrPos].text
    score = cols[scorePos].find('a').text
    print(id)
    print(descr)
    print(score)
    print(severity)
    print(created)
    print("=====================")

def getCVEData(cve):
  url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
  try:
    res = requests.get(url, proxies=proxies).json()
  except:
    print("Error while request to cve base")
    return None

  if res['totalResults'] <= 0:
    print("Can't find %s"%(cve))
    return None

  requestDate = res['timestamp']
  cve = res['vulnerabilities'][0]['cve']
  vulnStatus = cve['vulnStatus']
  name = cve['id']
  sourceIdentifier = cve['sourceIdentifier']
  published = cve['published']
  published = published[0:10] + " " + published[11:19]
  description = cve['descriptions'][0]['value']
  references = cve['references']

  metrics = cve['metrics']
  if len(metrics) >= 1:
    if 'cvssMetricV31' in metrics:
      metrics = metrics['cvssMetricV31'][0]['cvssData']
    elif 'cvssMetricV30' in metrics:
      metrics = metrics['cvssMetricV30'][0]['cvssData']
    else:
      print("Can't determine metric type")
      return None
    attackVector = metrics['attackVector']
    attackComplexity = metrics['attackComplexity']
    baseScore = metrics['baseScore']
    baseSeverity = metrics['baseSeverity']
  else:
    attackVector = "unknown"
    attackComplexity = "unknown"
    baseScore = 0.0
    baseSeverity = "unknown"

  result = {}
  result["name"] = name
  result["vuln_status"] = vulnStatus
  result["source_identifier"] = sourceIdentifier
  result["published"] = published
  result["description"] = description
  result["attack_vector"] = attackVector
  result["attack_complexity"] = attackComplexity
  result["base_score"] = baseScore
  result["base_severity"] = baseSeverity
  result["reference"] = references
  result["reference"] = json.dumps(result["reference"])

  return result

def cveExistInTable(cveName, table):
  sql = "select count(*) from " + table + " where name = '" + cveName + "'"
  count = 0
  try:
    conn = psycopg2.connect(dbname=db, user=user, password=password, host=host)
    cursor = conn.cursor()
    cursor.execute(sql)
    count = cursor.fetchone()[0]
    conn.commit()
  except (Exception, Error) as error:
    print(error)
    cursor.close()
    return True

  if count > 0:
    print("%s alredy added to database"%(cveName))
    return True

  return False

def addToDatabase(cve, table):
  sql = "insert into " + table + " (vuln_status_id, source_identifier_id, attack_vector_id, attack_complexity_id, base_severity_id, name, published, description, base_score, reference)"
  sql +=  " select "
  sql += "(select id from vuln_status where vuln_status.name = %s), "
  sql += "(select id from source_identifier where name = %s), "
  sql += "(select id from attack_vector where attack_vector.name = %s), "
  sql += "(select id from attack_complexity where attack_complexity.name = %s), "
  sql += "id, "
  sql += "%s, "
  sql += "%s, "
  sql += "%s, "
  sql += "%s, "
  sql += "%s"
  sql += "from base_severity where base_severity.name = %s"

  values = (cve["vuln_status"],
    cve["source_identifier"],
    cve["attack_vector"],
    cve["attack_complexity"],
    cve["name"],
    cve["published"],
    cve["description"],
    cve["base_score"],
    cve["reference"],
    cve["base_severity"])

  try:
    conn = psycopg2.connect(dbname=db, user=user, password=password, host=host)
    cursor = conn.cursor()
    cursor.execute(sql, values)
    conn.commit()
  except (Exception, Error) as error:
    print(error)
    cursor.close()
    return

  print("%s add to database"%(cve["name"]))

db = "cve"
user = "cve"
password = "cve"
host = "localhost"
http_proxy  = "http://someproxy:8080"
proxies = {
  "http"  : http_proxy,
  "https" : http_proxy
}
timeout = 6

#cvetrends not working!
#print("Receiving cve data from cvetrends")
#CVEList1 = getTopCVEList_cvetrends()

print("Receiving cve data from opencve.io")
CVEList = getTopCVEList_opencve()
print("Receiving cve data from circl.lu")
CVEList += getLastCVE_circl()
print("Removing duplicates")
CVEList = [*set(CVEList)]

print("Adding to DB")
for cveName in CVEList:
  if cveExistInTable(cveName, 'list3') == True:
    continue
  cve = getCVEData(cveName)
  if cve is None:
    continue
  addToDatabase(cve, 'list3')
  time.sleep(timeout)
print("Done")
