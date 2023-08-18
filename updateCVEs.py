#!/usr/bin/python3

import requests
import psycopg2
from psycopg2 import Error
import time
import json

def getCVEsToUpdate():
  CVEs = []

  sql = "select name from list3 where attack_vector_id = 5 or attack_complexity_id = 3 or base_severity_id = 5"
  try:
    conn = psycopg2.connect(dbname=db, user=user, password=password, host=host)
    cursor = conn.cursor()
    cursor.execute(sql)
    for row in cursor.fetchall():
      CVEs += row
    conn.commit()
  except (Exception, Error) as error:
    print(error)
    cursor.close()
    return None

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

def updateInDataBase(cve):
  sql = """
    update list3
    set attack_vector_id = (select id from attack_vector where name = '%s'),
      attack_complexity_id = (select id from attack_complexity where name = '%s'),
      base_severity_id = (select id from base_severity where name = '%s')
    where name = '%s'
  """ % (cve["attack_vector"], cve["attack_complexity"], cve["base_severity"], cve['name'])
  try:
    conn = psycopg2.connect(dbname=db, user=user, password=password, host=host)
    cursor = conn.cursor()
    cursor.execute(sql)
    conn.commit()
  except (Exception, Error) as error:
    print(error)
    cursor.close()
    return False
  return True

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

CVEs = getCVEsToUpdate()
for cveName in CVEs:
  cve = getCVEData(cveName)
  if cve["attack_vector"] != 'unknown' or cve["attack_complexity"] != 'unknown' or cve["base_severity"] != 'unknown':
    if updateInDataBase(cve) == True:
      print("%s updated in database"%(cve["name"]))
  time.sleep(timeout)
