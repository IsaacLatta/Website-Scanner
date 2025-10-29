#!/usr/bin/env python3
import sys, csv
from bs4 import BeautifulSoup
from urllib.parse import urljoin

BASE = "https://www.canada.ca"

html = sys.stdin.read()
soup = BeautifulSoup(html, "html.parser")

table = soup.select_one('table.wb-tables')
if not table:
    raise SystemExit("Could not find departments table")

out = csv.writer(sys.stdout)
out.writerow(["name","url","abbr","source"])
seen = set()

for tr in table.select('tbody > tr'):
    tds = tr.find_all('td')
    if len(tds) < 2:
        continue
    a = tds[0].find('a', href=True)
    if not a:
        continue
    name = " ".join(a.get_text(" ", strip=True).split())
    href = a['href'].strip()
    url = href if href.lower().startswith(('http://','https://')) else urljoin(BASE, href)
    abbr = " ".join(tds[1].get_text(" ", strip=True).split())
    key = (name, url)
    if key in seen:
        continue
    seen.add(key)
    out.writerow([name, url, abbr, "canada.ca/dept.html"])
