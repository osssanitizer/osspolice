# from github import Github
import utils
import os
import json
import shutil

logger = None
main = None


class Github:
    def __init__(self, detector):
        global logger, main
        main = detector
        logger = main.logger

        # config
        self.__timeout = main.REPO_CLONE_TIMEOUT
        self.__retries = main.REPO_CLONE_RETRIES

        # load accounts if available
        self.__accounts = {}
        if main.REPO_CREDENTIALS_FILE:
            try:
                import json
                with open(main.REPO_CREDENTIALS_FILE) as data_file:
                    self.__accounts = json.load(data_file)
            except Exception as e:
                logger.warn("Failed to read accounts file %s for github. Will clone repos without accounts: %s!",
                            main.REPO_CREDENTIALS_FILE, str(e))
        else:
            logger.warn("No accounts for Github supplied. Will clone repos without accounts!")

    def get_accounts(self):
        if not self.__accounts:
            logger.warn('No account accounts loaded for github')
            return '', ''

        import random
        random_id = random.randint(0, len(self.__accounts) - 1)
        userid = self.__accounts.keys()[random_id]
        passwd = self.__accounts[userid]
        return userid, passwd

    def get_github_handler(self):
        userid, passwd = self.get_accounts()
        try:
            if '@' in userid:
                userid = userid.split('@')[0]
            from github3 import GitHub
            return GitHub(userid, passwd)
        except Exception as e:
            logger.error("Failed to get github handler using accounts(%s, %s): %s",
                         userid, passwd, str(e))
            return None

    def get_repos(self, user):
        attempts = self.__retries
        while attempts:
            try:
                # github handler
                g = self.get_github_handler()
                if not g:
                    raise Exception("No github handler")

                # Then play with your Github objects:
                for repo in g.get_user().get_repos():
                    print repo.name
                    repo.edit(has_wiki=False)

            # timed out
            except utils.TimeoutException as te:
                logger.error("Error generating github repo list: %s", str(e))
                # try again
                attempts -= 1
                continue

            except Exception as e:
                logger.error("Failed to get github repo list: %s", str(e))
                return None

        logger.error("Giving up on generating github repo list!")
        return None

    def create_authenticated_repo_url(self, repo_url):
        try:
            import urlparse
            parsed_url = urlparse.urlparse(repo_url)
            if parsed_url == None:
                raise Exception("Failed to parse repo url: " + repo_url)

            userid, passwd = self.get_accounts()
            if '@' in userid:
                userid = userid.split('@')[0]

            repo_name = parsed_url.path.lstrip('/')
            auth_repo_url = parsed_url.scheme + "://" + userid + ":" + \
                            passwd + "@" + parsed_url.netloc + '/' + repo_name
            return repo_name, auth_repo_url

        except Exception as e:
            logger.error("Failed to create authenticated repo url from %s: %s", repo_url, str(e))
            return None

    def clone_repo(self, repo_name, repo_url, repo_path, branch=None):
        attempts = self.__retries
        while attempts:
            try:
                import git
                logger.info("cloning repo %s branch %s into %s (attempt %s timeout %s)",
                            repo_name, branch, repo_path, self.__retries - attempts, self.__timeout)

                # register timeout handler
                with utils.time_limit(self.__timeout):
                    if branch:
                        git.Git().clone(repo_url, repo_path, depth=1, branch=branch)
                    else:
                        git.Git().clone(repo_url, repo_path, depth=1)

                    return repo_name

            # timed out
            except utils.TimeoutException as te:
                logger.error("Repo clone for %s %s", repo_name, str(te))
                attempts -= 1
                if os.path.isdir(repo_path):
                    shutil.rmtree(repo_path)
                # try again
                continue

            except Exception as e:
                logger.error("Failed to clone repo %s: %s", repo_name, str(e))
                return None

        logger.error("Giving up on cloning github repo %s!", repo_name)
        return None

    def get_repo(self, repo_owner, repo_name):
        attempts = self.__retries
        while attempts:
            try:
                # github handler
                g = self.get_github_handler()
                if not g:
                    raise Exception("No github handler")

                repo = g.repository(repo_owner, repo_name)
                return repo

            # timed out
            except utils.TimeoutException as te:
                logger.error("Error getting github repo %s: %s", repo_name, str(te))
                # try again
                attempts -= 1
                continue

            except Exception as e:
                logger.error("Failed to get github repo %s: %s", repo_name, str(e))
                return None

        logger.error("Giving up on getting github repo %s!", repo_name)
        return None

    def get_commits(self, repo_owner, repo_name):
        from github3 import GitHubError
        attempts = self.__retries
        while attempts:
            try:
                # github handler
                g = self.get_github_handler()
                if not g:
                    raise Exception("No github handler")

                repo = g.repository(repo_owner, repo_name)
                commits = repo.iter_commits()  # [commit for commit in repo.iter_commits()]
                # for commit in commits:
                #    print commits[0].to_json()['commit']['committer']['date']
                return repo, commits

            except GitHubError as ghe:
                if str(ghe.code) == '403':
                    logger.error("get_tags: %s", str(ghe))
                    attempts -= 1
                    continue
                else:
                    logger.error("get_tags: %s, giving up!", str(ghe))
                    break

            # timed out
            except utils.TimeoutException as te:
                logger.error("Error getting github repo commits for repo %s: %s", repo_name, str(te))
                # try again
                attempts -= 1
                continue

            except Exception as e:
                logger.error("Failed to get github repo commits for repo %s: %s", repo_name, str(e))
                return None

        logger.error("Giving up on getting github repo releases for repo %s!", repo_name)
        return None

    def get_tags(self, repo_owner, repo_name):
        from github3 import GitHubError
        attempts = self.__retries
        while attempts:
            try:
                # github handler
                g = self.get_github_handler()
                if not g:
                    raise Exception("No github handler")

                repo = g.repository(repo_owner, repo_name)
                if not repo:
                    logger.error("repo doesn't exist: %s/%s, giving up!", repo_owner, repo_name)
                    break

                tags = repo.iter_tags()
                return repo, tags

            except GitHubError as ghe:
                if str(ghe.code) == '403':
                    logger.error("get_tags: %s", str(ghe))
                    attempts -= 1
                    continue
                else:
                    logger.error("get_tags: %s, giving up!", str(ghe))
                    break

            # timed out
            except utils.TimeoutException as te:
                logger.error("Error getting github repo tags for repo %s: %s", repo_name, str(te))
                # try again
                attempts -= 1
                continue

            except Exception as e:
                logger.error("Failed to get github repo tags for repo %s: %s", repo_name, str(e))
                return None, None

        logger.error("Giving up on getting github repo releases for repo %s!", repo_name)
        return None, None

    def blacklist_account(self, idx):
        if self.__accounts and idx in self.__accounts:
            del self.__accounts[idx]

    def add_accounts(self):
        pass

    def insert_tags_db(self, gh_id, repo_owner, repo_name, tags_commits):
        if not main.ndb:
            logger.error("native postgres database is not available! Ignoring!")
            return

        # refer to: proj-crawler/src/util/store_gitinfo.py
        full_name = repo_owner + '/' + repo_name
        for tag, commit in tags_commits:
            # information from summary
            tag_json = tag.to_json()
            tag_name = tag_json['name']
            zipball_url = tag_json['zipball_url']
            tarball_url = tag_json['tarball_url']
            commit_url = tag_json['commit']['url']
            commit_sha = tag_json['commit']['sha']
            commit_details = commit.to_json()
            commit_tree = commit_details['commit']['tree']['url']
            commit_date = commit_details['commit']['committer']['date']
            commit_message = commit_details['commit']['message']
            comment_url = commit_details['comments_url']
            if 'stats' in commit_details:
                commit_stats = commit_details['stats']
            else:
                commit_stats = ''
            comment_count = commit_details['commit']['comment_count']
            committer = commit_details['commit']['committer']
            author = commit_details['commit']['author']
            main.ndb.insert_table(table_name="repository_versions", insert_map={
                "gh_id": gh_id, "full_name": full_name, "name": tag_name, "zipball_url": zipball_url,
                "tarball_url": tarball_url, "commit_url": commit_url, "tree": commit_tree, "sha": commit_sha,
                "date": commit_date, "message": commit_message, "comment_url": comment_url,
                "comment_count": comment_count, "committer": json.dumps(committer), "author": json.dumps(author),
                "stats": json.dumps(commit_stats), "commit_path": ""})
        main.ndb.update(setmap={'tag_count': len(tags_commits)}, filtermap={'gh_id': gh_id})

    def get_tags_commits(self, repo_owner, repo_name, insertdb=False, gh_id=None):
        from github3 import GitHubError
        attempts = self.__retries
        repo = None
        tags_commits = []
        count = 0

        # for large repos we limit querying the server
        while attempts or (main.MAX_REPO_TAGS_QUERY and count < main.MAX_REPO_TAGS_QUERY):
            idx = 0
            try:
                # github handler
                g = self.get_github_handler()
                if not g:
                    raise Exception("No github handler")

                repo = g.repository(repo_owner, repo_name)
                if not repo:
                    logger.error("repo doesn't exist: %s/%s, giving up!", repo_owner, repo_name)
                    break

                for tag in repo.iter_tags():

                    # for large repos we limit querying the server
                    if main.MAX_REPO_TAGS_QUERY and idx > main.MAX_REPO_TAGS_QUERY:
                        break
                    if idx <= count:
                        idx += 1
                        continue
                    else:
                        tags_commits.append((tag, repo.commit(tag.to_json()['commit']['sha'])))
                        idx += 1
                        count += 1

                # insertdb
                if insertdb:
                    self.insert_tags_db(gh_id=gh_id, repo_owner=repo_owner, repo_name=repo_name,
                                        tags_commits=tags_commits)
                return repo, tags_commits

            except GitHubError as ghe:
                if str(ghe.code) == '403':
                    logger.error("get_tags_commits count %d idx %d: %s", count, idx, str(ghe))
                    attempts -= 1
                    continue
                else:
                    logger.error("get_tags_commits count %d idx %d: %s, giving up!", count, idx, str(ghe))
                    break

            except Exception as e:
                logger.error("failed to get tags for repo %s after collecting %d tags: %s", repo_name, count, str(e))
                return None, None

        logger.error("Giving up on collecting tags/commits for repo %s after %d tags/commits", repo_name, count)
        return repo, tags_commits

    def get_tags_commits_sorted_by_date(self, repo_owner, repo_name):

        import time
        import datetime
        import collections

        # get all tags and commits
        repo, tags_commits = self.get_tags_commits(repo_owner, repo_name)
        if not repo or not tags_commits:
            logger.error("no tags/commits available to sort")
            return None, None

        # get tags and commits along with their commit dates
        commit_date_map = {}
        try:
            for tag, commit in tags_commits:
                date = commit.to_json()['commit']['committer']['date']
                dt = time.mktime(datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ").timetuple())
                commit_date_map[dt] = (tag, commit)

            # sort tags
            sorted_tags_commits = collections.OrderedDict(sorted(commit_date_map.items(), reverse=True))
            return repo, sorted_tags_commits
        except Exception as e:
            logger.error("failed to get sorted tags and commits for repo %s: %s", repo_name, str(e))
            return None, None

    def dates_apart(self, start, end):
        distance = main.MIN_REPO_VERSIONS_DISTANCE
        if not distance:
            distance = 60
        return ((end.year - start.year) * 12 + (end.month - start.month)) / distance

    def get_tag_count_from_db(self, repo_name, repo_table_name='repositories'):
        tag_count = -1
        try:
            tag_count = main.ndb.query_table(repo_table_name, 'tag_count', full_name=repo_name)[0][0][0]
        except:
            logger.error("failed to get tag count from database for repo: %s!", repo_name)
        return tag_count

    def get_tags_from_db(self, full_name, version_table_name='repository_versions', return_obj=True):
        import time
        import datetime
        import collections

        # query all tags from db
        tags = main.ndb.query_table(version_table_name, 'name', 'sha', 'date', full_name=full_name)[0]
        commit_date_map = {}
        for tag in tags:
            name, sha, dt = tag
            dt_obj = time.mktime(datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%SZ").timetuple())
            commit_date_map[dt_obj] = (name, sha)
        sorted_tags_commits = collections.OrderedDict(sorted(commit_date_map.items(), reverse=True))

        # github handler
        g = self.get_github_handler()
        if not g:
            raise Exception("No github handler")

        repo_owner, repo_name = full_name.split('/')
        if return_obj:
            repo = g.repository(repo_owner, repo_name)
        else:
            repo = full_name
        return repo, sorted_tags_commits

    def get_major_tags(self, all_tags):
        # filter all the tags by name, X.Y.Z, X_Y_Z
        # search the version string in the tag, and then group them, filter out rc/beta/alpha etc.
        import re
        PTN_VERSION_1 = re.compile("^(\w+)$")
        PTN_VERSION_2 = re.compile("^(\w+)[.\-+](\w+)$")
        PTN_VERSION_3 = re.compile("^(\w+)[.\-+](\w+)[.\-+](\w+)$")
        PTN_VERSION_4 = re.compile("^(\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)$")
        PTN_VERSION_5 = re.compile("^(\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)$")
        PTN_VERSION_6 = re.compile("^(\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)$")
        PTN_VERSION_7 = re.compile("^(\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)$")
        PTN_VERSION_8 = re.compile(
            "^(\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)$")
        PTN_VERSION_9 = re.compile(
            "^(\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)$")
        PTN_VERSION_10 = re.compile(
            "^(\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)[.\-+](\w+)$")

    def clone_tags(self, repo_url, repo_path='/tmp'):

        # first embed user account credentials in repo url
        repo_name, repo_url = self.create_authenticated_repo_url(repo_url)
        if not repo_name or not repo_url:
            logger.error("Failed to parse repo url %s", repo_url)
            return None

        # get all tags (sorted by dates, latest to earliest)
        tag_count = self.get_tag_count_from_db(repo_name)
        if tag_count is None or tag_count <= -1:
            logger.info("haven't checked repo tags %s yet! directly query GitHub to get this information", repo_name)
            repo_owner, repo_name = repo_name.split('/')
            repo, sorted_tags_commits = self.get_tags_commits_sorted_by_date(repo_owner, repo_name)
            if not repo or not sorted_tags_commits:
                logger.error("Failed to get tags/commits for repo %s", repo_name)
                return None
        elif tag_count == 0:
            # no tags found
            return None
        else:
            logger.info("get the %d tags information for repo %s from the postgresql database", tag_count, repo_name)
            full_name = repo_name
            repo_owner, repo_name = repo_name.split('/')
            repo, sorted_tags_commits = self.get_tags_from_db(full_name=full_name)

        # get dates range
        min_date = utils.ts_to_date(sorted_tags_commits.keys()[-1])
        max_date = utils.ts_to_date(sorted_tags_commits.keys()[0])
        num_tags = len(sorted_tags_commits)
        logger.info("Found %d tags from %s to %s", num_tags, str(min_date), str(max_date))

        if False and main.INDEX_MAJOR_VERSIONS:
            # not implemented yet!
            # group tags by major version as requested in config, filter out all the versions that is not major version
            print (sorted_tags_commits)
            sorted_grouped_tags_commits = []

        else:
            # group tags by dates distance as requested in config
            import itertools
            self.last_date = max_date
            grouped_tags_commits = {}
            for key, grp in itertools.groupby(sorted_tags_commits.items(),
                                              key=lambda (ts, data): self.dates_apart(max_date, utils.ts_to_date(ts))):
                ts = None
                for t, tags_commits in list(grp):
                    if not ts:
                        ts = t
                        grouped_tags_commits[ts] = []
                    grouped_tags_commits[ts].append(tags_commits)

            # if more tags are available than what we can handle
            num_tags = len(grouped_tags_commits)
            if main.MAX_REPO_VERSIONS and num_tags > main.MAX_REPO_VERSIONS:
                num_tags = main.MAX_REPO_VERSIONS

            # sort them and start cloning
            import collections
            sorted_grouped_tags_commits = collections.OrderedDict(
                itertools.islice(sorted(grouped_tags_commits.items(), reverse=True), num_tags))

        cloned_versions = []
        logger.info("%d sorted grouped tags commits", num_tags)

        # iterate over the date-grouped and sorted list of tags to clone
        # the latest tag from each group
        for ts, tags_commits_list in sorted_grouped_tags_commits.items():
            logger.info("%s, %s", utils.ts_to_date_str(ts), tags_commits_list)

            # pick the latest (top) from the group
            tag, commit = tags_commits_list[0]
            if hasattr(tag, 'to_json'):
                # if generated from GitHub api
                branch = tag.to_json()['name']
            else:
                # if fetched from db, the object is plain string!
                branch = tag
            # branch may contain '_' in the path
            branch_name = repo_owner + '_' + repo_name + '_' + branch.replace('/', '_')
            clone_path = repo_path + '/' + branch_name

            # check if the repo tag is already cloned
            import os
            if os.path.isdir(clone_path):
                if os.path.exists(clone_path + "/.git"):
                    logger.info("repo %s branch %s clone exists at %s. skipping clone",
                                repo_name, branch, clone_path)
                    continue
                else:
                    # dir exists but not a git repo, delete it
                    import shutil
                    shutil.rmtree(clone_path)

            if not self.clone_repo(repo_name, repo_url, repo_path + '/' + branch_name, branch=branch):
                logger.error("failed to cloned repo %s branch %s", repo_name, branch)
            else:
                cloned_versions.append((branch, clone_path))
        return cloned_versions


if __name__ == '__main__':
    import sys
    import detector

    if len(sys.argv) < 2:
        print "usage: " + sys.argv[0] + " repo_url [clone_path] [branch]"
        exit(1)

    repo_path = None
    repo_url = sys.argv[1]
    if len(sys.argv) > 2:
        repo_path = sys.argv[2]
    if len(sys.argv) > 3:
        branch = sys.argv[3]

    main = detector.Detector(mode='Indexing')
    gh = Github(main)

    # first embed user account credentials in repo url
    repo_name, repo_url = gh.create_authenticated_repo_url(repo_url)
    if not repo_name or not repo_url:
        print "Failed to parse repo url " + repo_url
        exit(1)

    repo_owner, repo_name = repo_name.split('/')
    repo, tags = gh.get_tags_commits_sorted_by_date(repo_owner, repo_name)
    for tag in tags:
        print tag.to_json()
    # cloned_versions = gh.clone_tags(repo_url)
    # if cloned_versions:
    #    print cloned_versions