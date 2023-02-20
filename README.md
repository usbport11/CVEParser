# CVEParser
Get CVE from services.nvd.nist.gov and add to postgres

<b>DB prepare</b><br><br>
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
