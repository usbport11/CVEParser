# CVEParser
Get CVE from services.nvd.nist.gov and add to postgres <br>
Code that get data from sites CVE trends and OpenCVE get from open ready examples

<b>Python prepare</b><br>
<pre>
pip3 install requests
pip3 install bs4
pip3 install psycopg2
</pre>

<b>DB prepare</b><br>
<pre>
apt install postgresql
</pre>

Create database
<pre>
create database cve;
</pre>

Create table
<pre>
create table list (
  id SERIAL PRIMARY KEY,
  name VARCHAR(32),
  vuln_status VARCHAR(32),
  published TIMESTAMP,
  description TEXT,
  attack_vector VARCHAR(32),
  attack_complexity VARCHAR(16),
  base_score real,
  base_severity VARCHAR(16)
);
</pre>

Create user and grant access
<pre>
create user cve with password 'cve';
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cve;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cve;
</pre>
