from common import FileType, common_leaf_types
from collections import Counter
from metric.levenshtein_wrapper import levenshtein_batch


def get_matched_top_directory(main, tree, parent, result_type, logger=None):
    # native [repo -> ]branch -> dir
    # java repo -> dir
    parent_type, _ = parent.split('-', 1)
    all_children = [child for child in tree[parent].keys() if '-' in child]
    all_top_dir_ids = []
    for child in all_children:
        if tree[parent][child] <= 0 and logger is not None:
            logger.warn("Strange! parent %s child %s have negative frequency %s!", parent, child, tree[parent][child])

        child_type, child_id = child.split('-', 1)
        if result_type == 'java':
            all_top_dir_ids.append(child_id)
        elif result_type == 'native':
            if parent_type == 'branch' and child_type == 'dir':
                all_top_dir_ids.append(child_id)
            elif parent_type == 'repo' and child_type == 'branch':
                all_top_dir_ids.extend(get_matched_top_directory(main=main, tree=tree, parent=child,
                                                                 result_type=result_type, logger=logger))
            else:
                raise Exception("Unexpected parent_type: %s, child_type: %s" % (parent_type, child_type))
        else:
            raise Exception("Unexpected result_type: %s" % result_type)
    return all_top_dir_ids


def get_matched_leaves(main, tree, parent, result_type, matched_tree=None, logger=None):
    parent_type, _ = parent.split('-', 1)
    all_children = [child for child in tree[parent].keys() if '-' in child]
    # leaves are not present in tree
    all_leaves = []
    for child in all_children:
        child_type, _ = child.split('-', 1)

        # for java, the tree is only matched tree, simply go to the leaves recursively
        # for native, there are a couple of filters when going up, so we need to re-apply them when going down
        if tree[parent][child] <= 0:
            if child_type in common_leaf_types:
                continue
            elif logger is not None:
                logger.warn("Strange! parent %s child %s have negative frequency %s!", parent, child,
                            tree[parent][child])

        if child in tree:
            if main.USE_GROUPED_MATCH:
                # Handle native grouped match rules
                if result_type == 'native' and not child_type == 'branch' and child_type not in common_leaf_types:

                    # Rule 1: native, regarding source file, if the child is a source file (not header),
                    # and has no function matches, then exclude it, all file should have filetype!
                    if (child_type == 'file' and 'filetype' in tree[child]
                            and tree[child]['filetype'] in [FileType.C, FileType.CPP]
                            and 'grouped_funcfreq' in tree[child] and 'grouped_funcnamefreq' in tree[child]
                            and tree[child]['grouped_funcfreq'] + tree[child]['grouped_funcnamefreq']
                            < main.MIN_GROUPED_FUNCFREQ):
                        continue

                    # Rule 2: native, regarding license, if the child has license file
                    if (parent_type == 'dir' and child_type == 'dir' and 'license' in tree[child]
                            and tree[child]['license']):
                        continue

                    # Rule 3: native, regarding refcnt, if the child has much higher refcnt than the rest of the child
                    if parent_type == 'dir' and child_type in main.GROUPED_NODE_TYPES and len(all_children) >= 2:
                        # for each child, compare it with all other child in the same folder
                        import numpy as np
                        other_children_avg_refcnt = np.mean(
                            [tree[other_child]['refcnt'] for other_child in all_children if other_child != child])
                        if tree[child]['refcnt'] >= other_children_avg_refcnt * main.MAX_GROUPED_REFCNT_RATIO:
                            continue

                    # Rule 4: native, regarding ratio, if the child has low match ratio (use GROUPED_NODE_TYPES to
                    # control the types of nodes to apply this filtering)
                    if 'grouped_featcnt' in tree[child]:
                        child_match_ratio = float(tree[child]['grouped_featfreq']) / tree[child]['grouped_featcnt'] \
                            if tree[child]['grouped_featcnt'] else 0
                    else:
                        child_match_ratio = float(tree[child]['featfreq']) / tree[child]['featcnt'] \
                            if tree[child]['featcnt'] else 0
                    if child_type in main.GROUPED_NODE_TYPES and child_match_ratio <= main.MIN_GROUPED_PERCENT_MATCH:
                        continue

                # Handle java grouped match rules
                if result_type == 'java' and child_type not in common_leaf_types:
                    # Rule 3: java, regarding refcnt, if the child has much higher refcnt than the rest of the child
                    if parent_type == 'dirs' and child_type in main.GROUPED_NODE_TYPES and len(all_children) >= 2:
                        # for each child, compare it with all other child in the same folder
                        import numpy as np
                        other_children_avg_refcnt = np.mean(
                            [tree[other_child]['refcnt'] for other_child in all_children if other_child != child])
                        if tree[child]['refcnt'] >= other_children_avg_refcnt * main.MAX_GROUPED_REFCNT_RATIO:
                            continue

                    # Rule 4: java, regarding ratio, if the child has low match ratio (use GROUPED_NODE_TYPES to
                    # control the types of nodes to apply this filtering)
                    # if 'grouped_featcnt' in tree[child]:
                    #     child_match_ratio = float(tree[child]['grouped_featfreq']) / tree[child]['grouped_featcnt'] \
                    #         if tree[child]['grouped_featcnt'] else 0
                    # else:
                    #     child_match_ratio = float(tree[child]['featfreq']) / tree[child]['featcnt'] \
                    #         if tree[child]['featcnt'] else 0
                    # if child_type in main.GROUPED_NODE_TYPES and child_match_ratio <= main.MIN_GROUPED_PERCENT_MATCH:
                    #     continue

            if child_type in common_leaf_types:
                all_leaves.append(child)
            else:
                all_leaves.extend(get_matched_leaves(main=main, tree=tree, parent=child, result_type=result_type,
                                                     matched_tree=matched_tree, logger=logger))

        else:
            # this must be leaf
            all_leaves.append(child)

        # update the matched tree
        if matched_tree is not None:
            matched_tree.setdefault(parent, [])
            matched_tree[parent].append(child)

    return all_leaves


def get_repo_groups(main, repo_matches, tree, result_type="java", logger=None):
    """
    Matched Content Group:
    1. Get the unique features mapped from each software, and compute their simhash based on these features.
    If two matched software are similar, then they are in the same group.

    Contained Content Group:
    2. Get the simhash of each branch/repo, and compare them to see whether there are two matched software that are
    similar, if yes, then they are in the same group.

    TODO: DON'T KNOW YET!
    Filename Group:
    3. If the matched file names of repos are similar, then cluster/rank them by comparing them with the artifact name
    e.g. sqlite.h in xx/kroger should be down-voted when compared with xx/sqlite3

    4. Iterate through the name of the matched files, if they are matched in more than K repos (i.e. popular), pick
        the one with closest name?

    :param repo_matches: dict, maps repo name -> details for all matched versions
    :param tree: dict, maps node to node attribute and children
    :param result_type: java or native
    :return: repo names, mapped to group id
    """
    if len(repo_matches) == 0:
        if logger:
            logger.info("There is %d repo matches, no need to get repo groups!", len(repo_matches))
        return {}, {}, {}

    from utils import get_simhash_distance, get_simhash
    from itertools import combinations, product
    repo2groups = {}

    # Case 1: repo mapped to matched content id
    repo2matched_leaves = {}
    repo2matched_tree = {}
    repo2matched_ids = {}
    for repo, versions in repo_matches.items():
        # pick the highest match with score for a particular software
        if result_type == "java":
            sorted_versions = sorted(versions, key=lambda k: k[-2], reverse=True)
        elif result_type == "native":
            sorted_versions = sorted(versions, key=lambda k: k[5], reverse=True)
        else:
            raise Exception("Unexpected result type: %s!" % result_type)
        # the parameters in native are: version, branch_id, target_license, featfreq, featcnt, score, normscore,
        #   strfreq, varfreq, funcfreq, funcnamefreq
        # the parameters in java are: version, software_pathhash, featfreq, featcnt, score, normscore
        repo_id = sorted_versions[0][1]
        repo2matched_tree.setdefault(repo, {})
        repo2matched_leaves.setdefault(repo, [])
        matched_leaves = get_matched_leaves(main=main, tree=tree, parent=repo_id, matched_tree=repo2matched_tree[repo],
                                            result_type=result_type, logger=logger)
        matched_leaf_features = Counter(matched_leaves)
        if len(matched_leaf_features) == 0:
            if logger:
                logger.error("repo %s doesn't have any matched leaves, this is weird!", repo)
            repo2matched_ids[repo] = 0
            continue

        matched_id = get_simhash(items=[leaf.split('-')[-1] for leaf in matched_leaf_features.keys()])
        repo2matched_ids[repo] = matched_id
        repo2matched_leaves[repo].extend(matched_leaf_features)
        if logger:
            logger.info("number of matched leaves for repo %s is %d (uniq %d), simhash id is %s",
                        repo_id, len(matched_leaves), len(matched_leaf_features), matched_id)
    if len(repo_matches) == 1:
        return {repo_matches.keys()[0]: 0}, repo2matched_leaves, repo2matched_tree

    # Case 2: repo mapped to contained content id
    repo2content_ids = {}
    for repo, versions in repo_matches.items():
        # each repo can mapped to all the versions' ids
        for matched_version in versions:
            version_id = matched_version[1]
            version_contained_ids = get_matched_top_directory(main=main, tree=tree, parent=version_id,
                                                              result_type=result_type, logger=logger)
            repo2content_ids.setdefault(repo, [])
            if len(version_contained_ids) >= 1:
                repo2content_ids[repo].extend(version_contained_ids)
            else:
                raise Exception("Unexpected! repo %s version %s doesn't have version content ids!" % (repo, version_id))

    # Case 3: repo mapped to matched filename set
    # repo2matched_filename_set = {}
    # distances = levenshtein_batch(sArr=None, strB=None, normalize=True)

    # Check whether two repos are in the same group
    for repo1, repo2 in combinations(repo_matches.keys(), r=2):
        if logger:
            logger.debug('repo1 %s, matched ids %s, repo2 %s, matched ids %s', repo1, repo2matched_ids[repo1],
                         repo2, repo2matched_ids[repo2])
            logger.debug('repo1 %s, content ids %s, repo2 %s, content ids %s', repo1, repo2content_ids[repo1],
                         repo2, repo2content_ids[repo2])
        matched_distance = get_simhash_distance(repo2matched_ids[repo1], repo2matched_ids[repo2])
        content_distance = min([get_simhash_distance(h1, h2) for h1, h2 in
                                product(repo2content_ids[repo1], repo2content_ids[repo2])])
        if (matched_distance <= main.MAX_GROUPED_RESULT_SIMHASH_DISTANCE
                or content_distance <= main.MAX_GROUPED_RESULT_SIMHASH_DISTANCE):
            if repo1 in repo2groups:
                group1 = repo2groups[repo1]
            else:
                group1 = {repo1}
            if repo2 in repo2groups:
                group2 = repo2groups[repo2]
            else:
                group2 = {repo2}
            merged_group = group1 | group2

            for repo in merged_group:
                repo2groups[repo] = merged_group
        else:
            repo2groups.setdefault(repo1, {repo1})
            repo2groups.setdefault(repo2, {repo2})

    repo2groupids = {}
    group_id = 0
    for repo, group in repo2groups.items():
        if repo not in repo2groupids:
            for rg in group:
                repo2groupids[rg] = group_id
            group_id += 1

    return repo2groupids, repo2matched_leaves, repo2matched_tree
