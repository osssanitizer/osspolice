#!/usr/bin/env python

import sys
import urllib2 as url
from bs4 import BeautifulSoup as Soup

URL_BASE = "http://www.appbrain.com/stats/libraries/"
HEADER = {'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36'}

if __name__ == "__main__":

    category = sys.argv[1]

    request = url.Request(URL_BASE + category, headers = HEADER)
    page = url.urlopen(request)
    soup = Soup(page)

    rows = soup.find_all("div", {"class" : "row stats-library-row"})

    for elem in rows:
        div_name = elem.contents[1]
        name = div_name.contents[1].contents[3].contents[1].text
        print name.strip()
