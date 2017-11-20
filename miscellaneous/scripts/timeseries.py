#!/usr/bin/env python

import os
import sys
import datetime

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print "Usage: %s <path to log> [path to repo list]" % sys.argv[0]
		exit(1)

	repo_list = {}
	clone = {}
	scan = {}
	strs = {}

	count = 0
	if len(sys.argv) == 3 and os.path.isfile(sys.argv[2]) and os.path.exists(sys.argv[2]):
		import csv, json
		f = open(sys.argv[2])
		reader = csv.reader(f, delimiter=',')
		for repo_id, repo_name, repo_url, primary_language, all_languages, \
				subscribers_count, stargazers_count, forks_count, created_at, \
				updated_at, pushed_at, size in reader:

			# check file format
			if count == 0 and repo_id == "gh_id" and repo_name == "full_name" and \
				repo_url == "html_url" and primary_language == "primary_language" and \
				all_languages == "languages":
				count += 1
				continue
			elif count == 0:
				print ("Invalid repo list format")
				break

			# consider only c/c++ repos
			languages = json.loads(all_languages)
			if not "C" and not "C++" in languages:
				continue

			repo_list[int(repo_id)] = str(repo_url + ";" + size + ";" + primary_language)

	for line in open(sys.argv[1]):
		if not "clonning" in line and \
			not "scanning" in line and \
			not "Number" in line and \
			not "ERROR" in line:
			continue

		line = line.replace(",", " ")
		values = line.split(" ")
		tag = values[5].strip(" ")
		if tag != "ERROR" and tag != "INFO":
			print "unsupported tag " + tag
			exit(1)

		words = values[6:]
		ts_str = values[0] + " " + values[1]
		ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")

		#print tag, ts, words
		if tag == "ERROR":
			repo = None
			for word in words:
				if word.endswith(":"): #and type(word.rstrip(":")) == int:
					word = os.path.basename(word)
					repo = int(word.rstrip(":"))
					break
			if repo and repo in clone:
				del clone[repo]
			if repo and repo in scan:
				del scan[repo]
		elif tag == "INFO":
			if "clonning" in words:
				repo = None
				for word in words:
					#word = word.strip(' ')
					if word.endswith(":"): #and type(word.strip(":")) is int:
						repo = int(word.rstrip(":"))
						#print "clonning " + repo
						break
				if repo:
					clone[repo] = ts
			elif "scanning" in words:
				repo = None
				for word in words:
					if word.startswith("/"):
						path = os.path.dirname(word)
						if os.path.isdir(path):
							repo = int(os.path.basename(word))
							#print "scanning " + repo
							break

				if repo:
					scan[repo] = ts
					if repo in clone:
						start = clone[repo]
						end = ts
						diff = (end-start).total_seconds()
						clone[repo] = diff
			else:
				prev = repo = None
				for word in words:
					if not repo and prev and word == "=":
						repo = int(prev)
					if repo and prev and word.endswith('\n'):
						strs[repo] = int(word)
						break
					prev = word

				if repo and repo in scan:
					start = scan[repo]
					end = ts
					diff = (end-start).total_seconds()
					scan[repo] = diff

	print "repo, clone, scan, strings, size, lang, url"
	for key, value in clone.iteritems():
		repo_id = key
		clone_time = value
		print repo_id, clone_time,
		scan_time = num_strs = repo_url = repo_size = None
		if repo_id in scan and repo_id in strs:
			scan_time = scan[repo_id]
			num_strs = strs[repo_id]
			print scan_time, num_strs,
		if repo_id in repo_list:
			repo_url, repo_size, primary_language = repo_list[repo_id].split(";")
			print repo_size, primary_language, repo_url
		else:
			print
