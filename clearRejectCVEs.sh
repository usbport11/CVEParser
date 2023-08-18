#!/usr/bin/bash

PGPASSWORD=cve psql -U cve -h localhost -d cve -c "delete from list3 where description like '%** REJECT **%';"