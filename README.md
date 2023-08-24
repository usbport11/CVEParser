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

Crontab
<pre>
0 1 * * * /root/cve/cve.py > /root/cve/cve.log 2>&1
0 2 * * 6 /root/cve/updateCVEs.py > /root/cve/update.log 2>&1
0 3 * * 6 /root/cve/getHighCritCVE.py > /root/cve/highcrit.log 2>&1
0 2 * * 7 /root/cve/clearRejectCVEs.sh > /root/cve/clearReject.log 2>&1
</pre>

For web need files from jquery.
<ul>
<li>bootstrap.min.css</li>
<li>datatables.min.css</li>
<li>buttons.dataTables.min.css</li>
<li>jquery-3.5.1.js</li>
<li>jquery.dataTables.min.js</li>
<li>dataTables.buttons.min.js</li>
<li>buttons.colVis.min.js</li>
</ul>
