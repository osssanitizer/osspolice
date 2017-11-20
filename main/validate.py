# This file is responsible for validating the open-source status of apps. The steps are as follows:
# 1. load the list of apps (from search results) and their description (downloaded using playcrawl)
# 2. collect the developer related information related to an app, and optionally use scrapy to crawl
#   developer website to find open-source potentials.
# 3. for all the potential open-source links, clone them and check if they are hosting Android app source code. If they
#   are, get the source code, and compare against the features from the apk (both Java and Native).
#   If they match, then the developer complies with the source code requirement of GPL, o.w. violates.


import sys
import os
import logging
import csv
import re
import utils
import time
import glob
from os.path import exists, join, basename, splitext
from signature_java import get_input_list
from signature_java_constants import PB_SUFFIX
from proto.googleplay_pb2 import DocV2
from job_util import read_proto_from_file

oss_patterns = [re.compile("http[s]?://[^/]*github"), re.compile("http[s]?//[^/]*bitbucket")]

###########################################################
# init state
###########################################################
logger = None
stats_logger = None


def validate_links(main, links, app_path):
    # 1. check if the link is pointing to an Android app
    # 2. get the Java/Native features from app_path
    # 3. get the Java/Native features from link
    # 4. compare the features from link with app path to see if they match
    if not links or len(links) == 0:
        return []
    logger.warn("Not implemented yet! Returning all the links")
    return links

    logger.info("validating %d links for app %s", len(links), app_path)
    from searching_java import search_items
    strs, classes, normclasses, centroids = search_items(main=main, input_path=app_path, input_type='apk',
                                                         outdir=main.java_sig_dir, return_features=True)
    for link in links:
        logger.info("validating link %s", link)
        # clone the link

        # get all the java features

        strs, funcs, normclasses, centroids = '', '', '', ''


def get_domain(url):
    # Get domain from url
    # http://stackoverflow.com/questions/9626535/get-domain-name-from-url
    from urlparse import urlparse
    domain = ''
    try:
        parsed_uri = urlparse(url)
        domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    except Exception as e:
        logger.error("Error parsing url %s", str(e))
    return domain


def is_open_source_link(url):
    return any([domain_token in get_domain(url.lower()) for domain_token in ['github.', 'bitbucket.', 'gitlab.']])


def crawl_links(start_url, only_open_source=True):
    # use scrapy to crawl the open source links
    # check for existing crawl results
    raise Exception("Not implemented yet!")
    urls = []
    if only_open_source:
        return [url for url in urls if is_open_source_link(url=url)]
    else:
        return urls


def get_links(content, only_open_source=True):
    # use regular expression to find links
    # Reference: http://stackoverflow.com/questions/6883049/regex-to-find-urls-in-string-in-python
    url_pattern = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, content)
    if only_open_source:
        return [url for url in urls if is_open_source_link(url=url)]
    else:
        return urls


def validate_apk(main, app_path):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger
    logger.info("Validating apk %s", app_path)

    # 1. load the description for the app
    if not main.app_pb_load_dirs:
        logger.error("app_pb_load_dirs not available: %s!")
        exit(1)
    expected_pb_file = None
    for app_pb_load_dir in main.app_pb_load_dirs:
        potential_pb_path = join(app_pb_load_dir, splitext(basename(app_path))[0] + PB_SUFFIX)
        if exists(potential_pb_path):
            expected_pb_file = potential_pb_path
            break
        else:
            found_files = glob.glob(potential_pb_path.rsplit('-', 1)[0] + '-*')
            if len(found_files) > 0:
                expected_pb_file = found_files[0]
                break
    if not expected_pb_file:
        logger.error("%s doesn't have app pb for app %s", main.app_pb_load_dirs, app_path)
        return
    app_proto = DocV2()
    read_proto_from_file(app_proto, filename=expected_pb_file, binary=True)

    # 2. collect app details (developers/open source links) and optionally open source links from developer website
    app_details = app_proto.details.appDetails
    app_info = {}
    app_info['packageName'] = app_details.packageName
    app_info['versionCode'] = app_details.versionCode
    app_info['versionString'] = app_details.versionString
    app_info['installationSize'] = app_details.installationSize
    app_info['uploadDate'] = app_details.uploadDate
    app_info['numDownloads'] = app_details.numDownloads
    app_info['developerName'] = app_details.developerName
    app_info['developerEmail'] = app_details.developerEmail
    app_info['developerWebsite'] = app_details.developerWebsite
    app_info['appType'] = app_details.appType
    app_info['appCategory'] = app_details.appCategory
    app_info['title'] = app_proto.title
    app_info['developer'] = app_proto.creator
    app_info['descriptionHtml'] = app_proto.descriptionHtml
    app_info.setdefault('potentialLinks', [])
    app_info['potentialLinks'].extend(get_links(app_info['descriptionHtml']))
    if not main.ignore_developer_website and app_info['developerWebsite']:
        app_info['potentialLinks'].extend(crawl_links(start_url=app_info['developerWebsite']))
        app_info['developerWebsiteChecked'] = True

    # 3. for the open source links, check (a) if they are android apps (b) if the hosted code matches current app
    app_info['openSourceLinks'] = validate_links(main=main, links=app_info['potentialLinks'], app_path=app_path)
    app_info['isOpenSource'] = True if app_info['openSourceLinks'] and len(app_info['openSourceLinks']) > 0 else False
    redis = main.rrc.handle()
    redis.hmset(app_path, app_info)


def run_validator(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    if not len(argv) == 1:
        logger.error('expectes args: $apks_to_validate, but get: %s', argv)
        exit(1)

    input_path = argv[0]
    if not exists(input_path):
        logger.error("%s does not exist", input_path)
        exit(1)

    input_list = get_input_list(main=main, redis=main.rrc.handle(), redis_pipe=main.rrc.pipeline(),
                                input_path=input_path, path_as_id=True, skip_scanned=main.ignore_scanned)
    # deduplicate!
    input_list = list(set(input_list))

    # start crawling
    if input_list:
        # track progress
        count = len(input_list)
        logger.info("Validating %d applications", count)

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        pb = utils.Progressbar('Validating applications: ', count)
        pb.start()

        if main.QUEUING and main.QUEUING == "Celery":
            from celery import group
            from celery_tasks import validate_worker

            # group jobs
            job = group(validate_worker.s(app_path) for app_path in input_list)
            result = job.apply_async()

            # track worker progress
            completed = 0
            while (result.waiting()):
                completed += result.completed_count()
                if completed < count:
                    pb.update(completed)
                time.sleep(2)

        else:  # non-parallel instance

            count = 0

            # scan loop
            for app_path in input_list:
                # check for interruption
                if signal.caught():
                    break

                if validate_apk(main=main, app_path=app_path):
                    count += 1

                # update progressbar
                pb.update(count)

            if not signal.caught():
                pb.finish()
