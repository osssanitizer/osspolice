#!/usr/bin/python

###########################################################
# Constant values
###########################################################
skip_set = {'refcnt', 'simcnt', 'featcnt', 'uniqfeatcnt', 'strcnt', 'uniqstrcnt', 'varcnt', 'uniqvarcnt',
            'funcnamecnt', 'uniqfuncnamecnt', 'funccnt', 'uniqfunccnt', 'license', 'filetype', 'filename'}
leaf_types = {'str', 'var', 'func', 'funcname'}
internal_types = {'file', 'dir'}
common_leaf_types = {'str', 'var', 'func', 'funcname', 'strings', 'classes', 'normclasses', 'centroids'}


###########################################################
# Helper functions
###########################################################
def get_typed_key(typ, key):
    return str(typ) + '-' + str(key)


def get_untyped_key(key):
    return key.rsplit('-', 1)[-1]


def get_rtyped_key(typ, key):
    return 'r-' + typ + '-' + str(key)


def get_rkey(key):
    return 'r-' + str(key)


def get_labeled_typed_key(label, typ, key):
    return get_typed_key(typ=label, key=get_typed_key(typ=typ, key=key))


def get_labeled_key(label, index_key):
    return get_typed_key(typ=label, key=index_key)


def get_unlabeled_key(key):
    # Split from the right, because software id (e.g., com.mopub:mopub-sdk) may contain '-'
    typ, key = key.rsplit('-', 2)[-2:]
    return get_typed_key(typ=typ, key=key)


def get_uniq_feature_count_name(features_type):
    if type(features_type) in (str, unicode):
        if features_type == "strings":
            return "uniqstrcnt"
        elif features_type == "classes":
            return "uniqclassccnt"
        elif features_type == "normclasses":
            return "uniqnormclasscnt"
        elif features_type == "centroids":
            return "uniqcentroidcnt"
        elif features_type == "features":
            return "uniqfeatcnt"
        else:
            raise Exception("Unknown features_type: %s" % features_type)
    elif isinstance(features_type, list):
        return [get_uniq_feature_count_name(per_type) for per_type in features_type]
    else:
        raise Exception("Unknown type of features_type: %s" % features_type)


def get_feature_count_name(features_type):
    if type(features_type) in (str, unicode):
        if features_type == "strings":
            return "strcnt"
        elif features_type == "classes":
            return "classcnt"
        elif features_type == "normclasses":
            return "normclasscnt"
        elif features_type == "centroids":
            return "centroidcnt"
        elif features_type == "features":
            return "featcnt"
        else:
            raise Exception("Unknown features_type: %s" % features_type)
    elif isinstance(features_type, list):
        return [get_feature_count_name(per_type) for per_type in features_type]
    else:
        raise Exception("Unknown type of features_type: %s" % features_type)


def get_uniq_feature_freq_name(features_type):
    if type(features_type) in (str, unicode):
        # the uniqueness of feature frequencies, are only unique within files
        # across files, this may not be the globally unique number
        if features_type == "strings":
            return "uniqstrfreq"
        elif features_type == "classes":
            return "uniqclassfreq"
        elif features_type == "normclasses":
            return "uniqnormclassfreq"
        elif features_type == "centroids":
            return "uniqcentroidfreq"
        elif features_type == "features":
            return "uniqfeatfreq"
        else:
            raise Exception("Unknown features_type: %s" % features_type)
    elif isinstance(features_type, list):
        return [get_uniq_feature_freq_name(per_type) for per_type in features_type]
    else:
        raise Exception("Unknown type of features_type: %s" % features_type)


def get_feature_freq_name(features_type):
    if type(features_type) in (str, unicode):
        if features_type == "strings":
            return "strfreq"
        elif features_type == "classes":
            return "classfreq"
        elif features_type == "normclasses":
            return "normclassfreq"
        elif features_type == "centroids":
            return "centroidfreq"
        elif features_type == "features":
            return "featfreq"
        else:
            raise Exception("Unknown features_type: %s" % features_type)
    elif isinstance(features_type, list):
        return [get_feature_freq_name(per_type) for per_type in features_type]
    else:
        raise Exception("Unknown type of features_type: %s" % features_type)


class FileType:
    C = 'C'
    H = 'H'
    CPP = 'CPP'
    HPP = 'HPP'


SrcExtensions = ['.h', '.c', '.cc', '.cpp', '.c++', '.cxx', '.C', '.hh', '.hxx', '.hpp', '.H']
Ext2FileType = {'.c': FileType.C, '.h': FileType.H, '.cc': FileType.CPP, '.cpp': FileType.CPP,
                      '.c++': FileType.CPP, '.cxx': FileType.CPP, '.C': FileType.CPP,
                      '.hh': FileType.HPP, '.hxx': FileType.HPP, '.hpp': FileType.HPP, '.H': FileType.HPP}

