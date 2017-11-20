#!/usr/bin/env python

import sys
import redisclient
import config as appconfig


###########################################################
# Usage
###########################################################
def print_usage(argv):
    print ('usage: ./%s <kind> [--json]' % argv[0])


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage(sys.argv)
    else:
        kind = sys.argv[1]

    if len(sys.argv) == 3:
        if sys.argv[2] == '--json':
            json = True
        else:
            print_usage(sys.argv)
    else:
        json = False

    config = appconfig.Config()
    rc = redisclient.RedisClient(config, kind)
    if not rc:
        exit(1)

    if not json:
        print (rc.dbsize())
        print (rc.memused())
    else:
        json_output = '{"size":' + str(rc.dbsize()[0])
        json_output += ', "mem":' + str(rc.memused()[0])

    if kind.lower() == 'java':
        val = rc.handle().get("reposcnt")
        if not json:
            print val
        else:
            json_output += ', "repos":' + str(val)
    elif kind.lower() == 'native':
        val = rc.handle().get("repos")
        if not json:
            print val
        else:
            json_output += ', "repos":' + str(val)
    elif kind.lower() == 'native_version':
        val = rc.handle().get("softwares")
        versions = rc.handle().get("softwareversions")
        if not json:
            print 'softwares: %s, versions: %s' % (val, versions)
        else:
            json_output += ', "repos":' + str(val)
    elif kind.lower() == 'java_version':
        val = rc.handle().get("softwarescnt")
        versions = rc.handle().get("softwareversionscnt")
        if not json:
            print 'softwares: %s, versions: %s' % (val, versions)
        else:
            json_output += ', "repos":' + str(val)
    elif kind.lower() == 'result':
        all_keys = rc.handle().keys()
        native_keys_count = 0;
        java_keys_count = 0;
        apk_keys_count = 0;
        unknown_keys_count = 0
        for key in all_keys:
            if key.endswith(".so"):
                native_keys_count += 1
            elif key.endswith(".dex"):
                java_keys_count += 1
            elif key.endswith(".apk"):
                apk_keys_count += 1
            else:
                unknown_keys_count += 1
        if not json:
            print ('processed %d libs/dex now (%d libs, %d dex, %d apk, %d unkonwn)' %
                   (len(all_keys), native_keys_count, java_keys_count, apk_keys_count, unknown_keys_count))
        else:
            json_output += ', "all":' + str(len(all_keys))
            json_output += ', "libs":' + str(native_keys_count)
            json_output += ', "dex":' + str(java_keys_count)
            json_output += ', "apk":' + str(apk_keys_count)
            json_output += ', "unknown":' + str(unknown_keys_count)
    else:
        raise Exception("Unknown kind: %s" % kind)

    if json:
        json_output += '}'
        print json_output
    else:
        response = raw_input("Do you want to flush the database yes/no? [no]")
        if response.lower() == 'yes':
            if config.get("TYPE", "Redis") == "REDIS_CLUSTER":
                response = raw_input("You are trying to flush redis cluster, are you sure about flush (sure/no)? [no]")
                if response.lower() == 'sure':
                    rc.flush()
            else:
                rc.flush()
