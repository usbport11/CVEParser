#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup
import psycopg2
from psycopg2 import Error
import time
import json

def getHighCritical2023():
  urlHigh = "https://www.opencve.io/cve?tag=&cvss=high&search=CVE-2023"
  urlCrit = "https://www.opencve.io/cve?tag=&cvss=critical&search=CVE-2023"
  CVEs = []
  for page_num in range(1, 90):
    pagination = urlHigh + "&page=" + str(page_num)
    resp = requests.get(pagination, proxies=proxies)
    bs = BeautifulSoup(resp.text, 'lxml')
    res = bs.select('tr.cve-header > td > a > strong')
    for item in res:
      CVEs.append(item.text)
  for page_num in range(1, 40):
    pagination = urlCrit + "&page=" + str(page_num)
    resp = requests.get(pagination, proxies=proxies)
    bs = BeautifulSoup(resp.text, 'lxml')
    res = bs.select('tr.cve-header > td > a > strong')
    for item in res:
      CVEs.append(item.text)
  return CVEs

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

CVEs = getHighCritical2023()
for cveName in CVEs:
  if cveExistInTable(cveName, 'list3') == True:
    continue
  cve = getCVEData(cveName)
  addToDatabase(cve, 'list3')
  time.sleep(timeout)