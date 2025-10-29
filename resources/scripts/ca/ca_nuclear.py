#!/usr/bin/env python3
from bs4 import BeautifulSoup
import csv
import sys

# Assumed base URL (you can modify this if needed)
base_url = "https://nuclearsafety.gc.ca"
source = "nuclearsafety.gc.ca"

# Read HTML from stdin
html_content = sys.stdin.read()

# Parse HTML
soup = BeautifulSoup(html_content, 'html.parser')

# Find all rows
rows = soup.find_all('tr')

# Create CSV writer that outputs to stdout
writer = csv.writer(sys.stdout)

# Write header
writer.writerow(['name', 'url', 'abbr', 'source'])

for row in rows:
    # Find the second td (which contains the link)
    tds = row.find_all('td')
    if len(tds) >= 2:
        link_td = tds[1]
        link = link_td.find('a')
        
        if link:
            name = link.get_text(strip=True)
            href = link.get('href', '')
            
            # Build full URL
            if href:
                full_url = base_url + href
            else:
                full_url = ""
            
            # Write row: name, url, empty abbr, source
            writer.writerow([name, full_url, '', source])
        else:
            # If no link, just get the text (like "Cluff Lake Facility")
            name = link_td.get_text(strip=True)
            if name:
                writer.writerow([name, '', '', source])