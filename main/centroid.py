import math
import logging
import utils

try:
    from itertools import product
    from itertools import izip as zip
except Exception as e:
    print ("Seems you are using python3+, exception: %s" % str(e))

# Constant list
CENTROID_NAMES = ['centroids:x', 'centroids:y', 'centroids:z', 'centroids:w', 'centroids:xp', 'centroids:yp',
                  'centroids:zp', 'centroids:wp']
CENTROID_PREFIX = 'centroids'
INDEXING_CENTROID_PREFIX = 'indexingcentroids'


def get_typed_key(typ, key):
    return typ + '-' + str(key)


def get_typed_key_from_string(main, prefix, string):
    string_id = utils.get_key(main, string)
    return get_typed_key(typ=prefix, key=string_id)


# link to the centroid paper: http://dl.acm.org/citation.cfm?id=2568286
def get_centroid_coordinates(centroid):
    if type(centroid) == tuple:
        cx, cy, cz, w = centroid
    elif centroid.HasField('x'):
        cx = centroid.x
        cy = centroid.y
        cz = centroid.z
        w = centroid.w
    else:
        raise Exception("Unexpected type of centroid: %s" % centroid)
    return (cx, cy, cz, w)


def get_centroid_string_from_numbers(x, y, z, w, xp, yp, zp, wp):
    # Use higher precision for w values!
    return '%s(%0.4f,%0.4f,%0.4f,%d)(%0.4f,%0.4f,%0.4f,%d)' % (CENTROID_PREFIX, x, y, z, w, xp, yp, zp, wp)


def get_centroid_string(centroid, centroidinvoke):
    cx, cy, cz, w = get_centroid_coordinates(centroid)
    cxp, cyp, czp, wp = get_centroid_coordinates(centroidinvoke)
    return get_centroid_string_from_numbers(cx, cy, cz, w, cxp, cyp, czp, wp)


def get_typed_centroid_key(main, centroid, centroidinvoke):
    centroid_str = get_centroid_string(centroid=centroid, centroidinvoke=centroidinvoke)
    return get_typed_key_from_string(main=main, prefix=CENTROID_PREFIX, string=centroid_str)


def build_centroid_db(main, redis, centroid, centroidinvoke, cdd_range=0.01):
    """
    Add the centroid to the database. Map scores to centroid, and centroid to repo_id. *This method can be pipelined.*

    :param main: access to the hash function
    :param redis: access to the database
    :param centroid: (cx, cy, cz, w) attribute, where cx is average sequence number in the CFG, cy is the average
        number of outgoing edges of the node, cz is the depth of the loop of the node,
        w is sum(w_p + w_q), for any (p,q) edge in 3D-CFG.
    :param target_id: id of the target, can be file or software. But doesn't matter for this function.
    """
    # Map score to centroid
    centroid_key = get_typed_centroid_key(main=main, centroid=centroid, centroidinvoke=centroidinvoke)
    # adding centroid is slow, so we check whether the centroid has been processed before and skip if yes.
    if redis.exists(centroid_key):
        return

    # add centroid to the database
    if main.USE_CENTROID_BIN:
        indexing_centroids = get_similar_centroid_bins(centroid=centroid, centroidinvoke=centroidinvoke,
                                                       cdd_range=cdd_range, phase='index',
                                                       use_one_centroid_bin_in_index=main.USE_ONE_CENTROID_BIN_IN_INDEX)
        logging.debug("the target centroid is %s, indexing centroids are: %s" %
                      (get_centroid_string(centroid, centroidinvoke), indexing_centroids))
        for ic in indexing_centroids:
            typed_ic_key = get_typed_key_from_string(main=main, prefix=INDEXING_CENTROID_PREFIX, string=ic)
            redis.hincrby(typed_ic_key, centroid_key)
    else:
        cx, cy, cz, w = get_centroid_coordinates(centroid)
        cxp, cyp, czp, wp = get_centroid_coordinates(centroidinvoke)
        redis.zadd('centroids:x', cx, centroid_key)
        redis.zadd('centroids:y', cy, centroid_key)
        redis.zadd('centroids:z', cz, centroid_key)
        redis.zadd('centroids:w', w, centroid_key)
        redis.zadd('centroids:xp', cxp, centroid_key)
        redis.zadd('centroids:yp', cyp, centroid_key)
        redis.zadd('centroids:zp', czp, centroid_key)
        redis.zadd('centroids:wp', wp, centroid_key)


def get_similar_range(base, cdd_range):
    minimum = base * (1 - cdd_range) / (1 + cdd_range)
    maximum = base * (1 + cdd_range) / (1 - cdd_range)
    return [minimum, maximum]


def update_matched_set(redis, matched_set, name, min_val, max_val, max_result_count):
    result_count = redis.zcount(name=name, min=min_val, max=max_val)
    too_much = False
    if result_count > 0:
        if max_result_count < 0 or result_count <= max_result_count:
            matched_list = redis.zrangebyscore(name=name, min=min_val, max=max_val)
            if len(matched_set) == 0:
                matched_set.update(matched_list)
            else:
                matched_set.intersection_update(matched_list)
        else:
            too_much = True
    return too_much


def get_valid_digits_scale(n, k=1):
    scale = int(math.floor(math.log10(abs(n))))
    scale -= (k - 1)
    return scale


def round_valid_digits(n, k=1):
    # ref: http://stackoverflow.com/questions/32812255/round-floats-down-in-python-to-keep-one-non-zero-decimal-only
    if n == 0:
        return 0
    sgn = -1 if n < 0 else 1
    scale = -get_valid_digits_scale(n, k=k)
    factor = 10 ** scale
    return sgn * math.floor(abs(n) * factor) / factor


def round_to_scale(n, scale=1):
    if n == 0:
        return 0
    sgn = -1 if n < 0 else 1
    factor = 10 ** (-scale)
    return sgn * math.floor(abs(n) * factor) / factor


def fix_cross_boundary_values(rounded_value_base, test_value, scale):
    # find whether the test_value has crossed the boundary for rounded_value_base
    new_rounded_value_base = round_to_scale(test_value, scale=scale + 1)
    if new_rounded_value_base < rounded_value_base:
        return rounded_value_base
    elif new_rounded_value_base > rounded_value_base:
        return new_rounded_value_base
    else:
        return test_value


def get_truncated_bins(value, cdd_range=0.01, phase='index', use_one_centroid_bin_in_index=True):
    """
    This function is designated to optimize the search performance of centroid by truncating centroid values to
    allow hash based searching!

    The basic idea is to generate bins to allow fuzzy matching. Depending on parameter use_one_centroid_bin_in_index:
    (1) If we do overlapping bins, e.g., 102.4 maps to both 102 and 104 (delta = 2), then each bin is capable of representing
    [100, 104], [102, 106]. When we are searching 102.4, we can choose to search by 102 to get the [100, 104] range.
    (2) If we do non-overlapping bins, e.g., 102.4 maps to only 104 (delta = 4), then this bin only represents [102, 106].
    When we are searching 102.4, we can choose to search by 102 to get the [102, 106] range.

    Pros and Cons:
    (1) consumes more storage (2**8 possible bins for each indexing centroid), but performs better fuzzy range matching
    (2) consumes less storage, but have not as good matching on values that is around the cutoff of bins.

    Bins are extracted as follows:
    |x'-x|/(x+x') <= d
    (1-d)/(1+d)*x < x' < (1+d)/(1-d)*x
    delta = (1+d)/(1-d)*x - (1-d)/(1+d)*x
    1. delta is the absolute value range that is considered as similar to x.
    2. any value within this range should be tied to the closest bins, i.e. one/two values if within bins.

    NOTE: cdd_range is used in both indexing and searching! If you change the cdd_range to values other than 0, or 0.01,
    you should re-index everything!
    """
    if value == 0:
        return (value,)
    value_min, value_max = get_similar_range(base=value, cdd_range=cdd_range)

    # TODO: use_one_centroid_bin_in_index = True saves storage, but is slower, False vice versa.
    # Regarding bin interval,
    # If we use delta/2, then the correct covered range is [delta/2, delta], with [0, delta/2] incorrect range
    # If we use delta/4, then the correct covered range is strictly [delta/2]
    # If we use delta, then the correct covered range is [delta], with [delta] incorrect range
    num_bins = 0
    DELTA_DOMINATOR = 1
    if use_one_centroid_bin_in_index:
        # If we use one centroid bin in index, we need to search two bins at search time. This is slower.
        # Regarding bin interval,
        if phase == 'index':
            num_bins = 1
        elif phase == 'search':
            num_bins = 2
    else:
        # If we use two centroid bin in index, this blows up the storage. But we have less storage consumption.
        if phase == 'index':
            num_bins = 2
        elif phase == 'search':
            num_bins = 1

    try:
        # 1. use value max and value min to generate delta!
        interval = (value_max - value_min) / DELTA_DOMINATOR
        # 2. find the delta's scale and round x to delta's scale
        interval_scale = get_valid_digits_scale(interval, k=1)
        # rounded_value = round_to_scale(value, scale=delta_scale)
        rounded_value_base = round_to_scale(value, scale=interval_scale + 1)
        # 3. compute the new_delta based on rounded_value, keep two valid digits of the number and bin it!
        if rounded_value_base == 0:
            # This may be problematic, because the interval may be different for the same rounded_value_base!
            new_interval = round_valid_digits(interval, k=2)
        else:
            new_value_min, new_value_max = get_similar_range(base=rounded_value_base, cdd_range=cdd_range)
            new_interval = round_valid_digits((new_value_max - new_value_min) / DELTA_DOMINATOR, k=2)
        # 4. find the closest three bins for the current value
        kth_bin = int((value - rounded_value_base) / new_interval)
        kth_value = rounded_value_base + kth_bin * new_interval  # kth value is not going to cross the boundary!
        kplusth_value = kth_value + new_interval  # kplus may cross the boundary
        kplusth_value = fix_cross_boundary_values(rounded_value_base, kplusth_value, scale=interval_scale)
    except Exception as e:
        print ("Failed to compute bins for value: %s, with cdd_range: %s, exception: %s" % (value, cdd_range, str(e)))
        raise e

    if num_bins == 1:
        if abs(kplusth_value - value) < abs(value - kth_value):
            return (kplusth_value,)
        else:
            return (kth_value,)
    elif num_bins == 2:
        if kth_value == rounded_value_base and abs(kplusth_value - value) > abs(value - kth_value):
            # if closer to the rounded value base, then use one more bins, make num_bins = 3, get the closer one below.
            kminusth_bin = get_truncated_bins(rounded_value_base - new_interval, cdd_range=cdd_range, phase='index',
                                              use_one_centroid_bin_in_index=True)
            # return (kminusth_bin[0], kth_value, kplusth_value)
            return (kminusth_bin[0], kth_value)
        else:
            return (kth_value, kplusth_value)
    else:
        raise Exception("Unexpected number of bins specified: %s" % num_bins)


##############################################################################
# Get the centroids to index/search
##############################################################################
def get_similar_centroid_bins(centroid, centroidinvoke, cdd_range=0.01, phase='index',
                              use_one_centroid_bin_in_index=True):
    """
    This function is used at indexing time! To generate bins that we should build indexing on!

    :param main: detector object
    :param centroid: the centroid
    :param centroidinvoke: the centroid with invoke
    :return:
    """
    # in the worst case, one centroid will generate 2**8 = 256 centroids to index!
    x, y, z, w = get_centroid_coordinates(centroid=centroid)
    x_bins = get_truncated_bins(value=x, cdd_range=cdd_range, phase=phase,
                                use_one_centroid_bin_in_index=use_one_centroid_bin_in_index)
    y_bins = get_truncated_bins(value=y, cdd_range=cdd_range, phase=phase,
                                use_one_centroid_bin_in_index=use_one_centroid_bin_in_index)
    z_bins = get_truncated_bins(value=z, cdd_range=cdd_range, phase=phase,
                                use_one_centroid_bin_in_index=use_one_centroid_bin_in_index)
    w_bins = get_truncated_bins(value=w, cdd_range=cdd_range, phase=phase,
                                use_one_centroid_bin_in_index=use_one_centroid_bin_in_index)
    xp, yp, zp, wp = get_centroid_coordinates(centroid=centroidinvoke)
    xp_bins = get_truncated_bins(value=xp, cdd_range=cdd_range, phase=phase,
                                 use_one_centroid_bin_in_index=use_one_centroid_bin_in_index)
    yp_bins = get_truncated_bins(value=yp, cdd_range=cdd_range, phase=phase,
                                 use_one_centroid_bin_in_index=use_one_centroid_bin_in_index)
    zp_bins = get_truncated_bins(value=zp, cdd_range=cdd_range, phase=phase,
                                 use_one_centroid_bin_in_index=use_one_centroid_bin_in_index)
    wp_bins = get_truncated_bins(value=wp, cdd_range=cdd_range, phase=phase,
                                 use_one_centroid_bin_in_index=use_one_centroid_bin_in_index)
    similar_centroids = set()
    for xb, yb, zb, wb, xpb, ypb, zpb, wpb in product(x_bins, y_bins, z_bins, w_bins, xp_bins, yp_bins, zp_bins,
                                                      wp_bins):
        similar_centroids.add(get_centroid_string_from_numbers(xb, yb, zb, wb, xpb, ypb, zpb, wpb))
    return similar_centroids


def search_centroid_db(main, centroid_tuple_list, cdd_range=0.01, max_result_count=1000, logger=None):
    # NOTE: if USE_CENTROID_BIN is True, then the used cdd_range must be the same as the value used at indexing time!
    if cdd_range <= 0:
        return [get_typed_centroid_key(main=main, centroid=centroid, centroidinvoke=centroidinvoke)
                for centroid, centroidinvoke in centroid_tuple_list]

    centroids_matched = set()
    if main.USE_REDIS_PIPELINE:
        if main.USE_CENTROID_BIN:
            redis_pipe = main.jrc.pipeline()
            searched_str_set = set()
            for centroid, centroidinvoke in centroid_tuple_list:
                searching_centroids = get_similar_centroid_bins(centroid=centroid, centroidinvoke=centroidinvoke,
                                                                cdd_range=cdd_range, phase='search',
                                                                use_one_centroid_bin_in_index=main.USE_ONE_CENTROID_BIN_IN_INDEX)
                if logger:
                    logger.debug("the target centroid is %s, searching centroids are: %s" % (
                        get_centroid_string(centroid, centroidinvoke), searching_centroids))
                for search_centroid_str in searching_centroids:
                    if search_centroid_str not in searched_str_set:
                        searched_str_set.add(search_centroid_str)
                    else:
                        continue
                    search_centroid_key = get_typed_key_from_string(main=main, prefix=INDEXING_CENTROID_PREFIX,
                                                                    string=search_centroid_str)
                    redis_pipe.hkeys(search_centroid_key)
            result_centroids = redis_pipe.execute()
            for matched_centroids in result_centroids:
                if matched_centroids and len(matched_centroids):
                    centroids_matched.update(matched_centroids)

        else:
            # pipeline all the zcount queries!
            redis_pipe = main.jrc.pipeline()
            all_centroid_query_and_centroid_key_list = []
            queried_result_list = []
            queried_result_cache = {}
            for centroid, centroidinvoke in centroid_tuple_list:
                cx, cy, cz, w = get_centroid_coordinates(centroid)
                cxp, cyp, czp, wp = get_centroid_coordinates(centroidinvoke)
                centroid_key = get_typed_centroid_key(main=main, centroid=centroid, centroidinvoke=centroidinvoke)
                centroid_values = [cx, cy, cz, w, cxp, cyp, czp, wp]
                centroid_query_tuples = []
                for name, key in zip(CENTROID_NAMES, centroid_values):
                    query_tuple = (name, key)
                    centroid_query_tuples.append(query_tuple)
                    if query_tuple not in queried_result_cache:
                        min_val, max_val = get_similar_range(key, cdd_range=cdd_range)
                        queried_result_cache.setdefault(query_tuple, 0)
                        queried_result_list.append(query_tuple)
                        redis_pipe.zcount(name=name, min=min_val, max=max_val)
                all_centroid_query_and_centroid_key_list.append((centroid_query_tuples, centroid_key))
            queried_result_values = redis_pipe.execute()
            queried_range_list = []
            for key, value in zip(queried_result_list, queried_result_values):
                if value > 0 and (max_result_count < 0 or value <= max_result_count):
                    # queried_result_cache[key] = value
                    queried_range_list.append(key)
                    n, k = key
                    min_val, max_val = get_similar_range(base=k, cdd_range=cdd_range)
                    redis_pipe.zrangebyscore(name=n, min=min_val, max=max_val)
                else:
                    queried_result_cache[key] = value
            queried_range_values = redis_pipe.execute()
            for key, value in zip(queried_range_list, queried_range_values):
                queried_result_cache[key] = value

            # we have finished all the redis operations, focus on generating the results now!
            for centroid_query_tuples, centroid_key in all_centroid_query_and_centroid_key_list:
                final_set = set()
                IGNORED_COUNT = 0
                for query_tuple in centroid_query_tuples:
                    query_result = queried_result_cache[query_tuple]
                    if type(query_result) in (int, long):
                        if max_result_count >= 0 and query_result > max_result_count:
                            # doesn't affect the results
                            IGNORED_COUNT += 1
                        elif query_result == 0:
                            # nothing matches
                            final_set = set()
                            break
                    elif isinstance(query_result, list):
                        if len(final_set) == 0:
                            final_set.update(query_result)
                        else:
                            final_set.intersection_update(query_result)
                    else:
                        raise Exception("Unexpected query result type: %s!" % type(query_result))
                if len(centroid_query_tuples) == IGNORED_COUNT:
                    if logger:
                        logger.info("ignoring the search query for %s", centroid_key)
                    final_set.add(centroid_key)

                centroids_matched.update(final_set)

    else:
        if main.USE_CENTROID_BIN:
            redis = main.jrc.handle()
            searched_str_set = set()
            for centroid, centroidinvoke in centroid_tuple_list:
                searching_centroids = get_similar_centroid_bins(centroid=centroid, centroidinvoke=centroidinvoke,
                                                                cdd_range=cdd_range, phase='search',
                                                                use_one_centroid_bin_in_index=main.USE_ONE_CENTROID_BIN_IN_INDEX)
                if logger:
                    logger.debug("the target centroid is %s, searching centroids are: %s" % (
                        get_centroid_string(centroid, centroidinvoke), searching_centroids))
                for search_centroid_str in searching_centroids:
                    if search_centroid_str not in searched_str_set:
                        searched_str_set.add(search_centroid_str)
                    else:
                        continue
                    search_centroid_key = get_typed_key_from_string(main=main, prefix=INDEXING_CENTROID_PREFIX,
                                                                    string=search_centroid_str)
                    matched_centroids = redis.hkeys(search_centroid_key)
                    if matched_centroids and len(matched_centroids):
                        centroids_matched.update(matched_centroids)

        else:
            redis = main.jrc.handle()
            for centroid, centroidinvoke in centroid_tuple_list:
                cx, cy, cz, w = get_centroid_coordinates(centroid)
                cx_min, cx_max = get_similar_range(cx, cdd_range=cdd_range)
                cy_min, cy_max = get_similar_range(cy, cdd_range=cdd_range)
                cz_min, cz_max = get_similar_range(cz, cdd_range=cdd_range)
                w_min, w_max = get_similar_range(w, cdd_range=cdd_range)
                cxp, cyp, czp, wp = get_centroid_coordinates(centroidinvoke)
                cxp_min, cxp_max = get_similar_range(cxp, cdd_range=cdd_range)
                cyp_min, cyp_max = get_similar_range(cyp, cdd_range=cdd_range)
                czp_min, czp_max = get_similar_range(czp, cdd_range=cdd_range)
                wp_min, wp_max = get_similar_range(wp, cdd_range=cdd_range)

                final_set = set()
                all_too_much = True
                all_too_much &= update_matched_set(redis=redis, matched_set=final_set, name='centroids:x',
                                                   min_val=cx_min, max_val=cx_max, max_result_count=max_result_count)
                all_too_much &= update_matched_set(redis=redis, matched_set=final_set, name='centroids:y',
                                                   min_val=cy_min, max_val=cy_max, max_result_count=max_result_count)
                all_too_much &= update_matched_set(redis=redis, matched_set=final_set, name='centroids:z',
                                                   min_val=cz_min, max_val=cz_max, max_result_count=max_result_count)
                all_too_much &= update_matched_set(redis=redis, matched_set=final_set, name='centroids:w',
                                                   min_val=w_min, max_val=w_max, max_result_count=max_result_count)
                all_too_much &= update_matched_set(redis=redis, matched_set=final_set, name='centroids:xp',
                                                   min_val=cxp_min, max_val=cxp_max, max_result_count=max_result_count)
                all_too_much &= update_matched_set(redis=redis, matched_set=final_set, name='centroids:yp',
                                                   min_val=cyp_min, max_val=cyp_max, max_result_count=max_result_count)
                all_too_much &= update_matched_set(redis=redis, matched_set=final_set, name='centroids:zp',
                                                   min_val=czp_min, max_val=czp_max, max_result_count=max_result_count)
                all_too_much &= update_matched_set(redis=redis, matched_set=final_set, name='centroids:wp',
                                                   min_val=wp_min, max_val=wp_max, max_result_count=max_result_count)
                if len(final_set) == 0 and all_too_much:
                    # If nothing matched, return the minimum one!
                    centroid_key = get_typed_centroid_key(main=main, centroid=centroid, centroidinvoke=centroidinvoke)
                    if logger:
                        logger.info("ignoring the search query for %s", centroid_key)
                    final_set.add(centroid_key)
                centroids_matched.update(final_set)

    return centroids_matched
