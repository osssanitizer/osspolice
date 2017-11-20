#!/usr/bin/env python

import argparse


class Options(object):
    __arg_list = []

    def argv(self):
        return self.__mode, self.__arg_list

    def __init__(self, argv):
        parser = argparse.ArgumentParser(prog="detector",
                                         usage="usage: detector cmd [options] args",
                                         version="detector 1.0",
                                         description="Match ARM ELF binaries to git-based source repos, or"
                                                     "DEX/APK binaries to software artifacts, and source repos")
        subparsers = parser.add_subparsers(help='Command (e.g. index source, search binary, dump stats,'
                                                'java_index inpath type, java_search inpath type, apk_search apk, etc.)',
                                           dest='cmd')

        # Index sub-command
        parser_index = subparsers.add_parser('index', help='Index source repo(s)')
        parser_index.add_argument("arg", help="Path to source repo(s)")
        parser_index.add_argument("-d", "--dump", default=False, action='store_true', help="Dump all features")
        parser_index.add_argument("-s", "--stats", default=False, action='store_true',
                                  help="Dump stats for all features")

        # Search sub-command
        parser_search = subparsers.add_parser('search', help='Match lib(s) to repo(s)')
        parser_search.add_argument("arg", help="Path to binary file(s)")
        parser_search.add_argument("-d", "--dump", default=False, action='store_true', help="Dump all features")
        parser_search.add_argument("-s", "--stats", default=False, action='store_true',
                                   help="Dump stats for all features")
        parser_search.add_argument("-v", "--verbose", default=False, action='store_true',
                                   help="Dump the matched features and paths")

        # Signature sub-command
        parser_signature = subparsers.add_parser('signature', help='Extract signature for C/C++ repo(s)')
        parser_signature.add_argument("arg", help="Path to source repo(s)")
        parser_signature.add_argument("-d", "--dump", default=False, action='store_true', help="Dump all features")
        parser_signature.add_argument("-s", "--stats", default=False, action='store_true',
                                      help="Dump stats for all features")

        # JavaIndexing sub-command
        parser_java_index = subparsers.add_parser('java_index', help='Index java artifact(s)')
        parser_java_index.add_argument("arg", nargs='+', help="Path to java artifact(s) and the input type")
        parser_java_index.add_argument("-d", "--dump", default=False, action='store_true', help="Dump all features")

        # JavaSearching sub-command
        parser_java_search = subparsers.add_parser('java_search', help='Search java artifact(s) or apks')
        parser_java_search.add_argument("arg", nargs='+', help="Path to java artifact(s) and the input type")
        parser_java_search.add_argument("-d", "--dump", default=False, action='store_true', help="Dump all features")
        parser_java_search.add_argument("-v", "--verbose", default=False, action='store_true',
                                        help="Dump the matched features and paths")

        # JavaSignature sub-command
        parser_java_signature = subparsers.add_parser('java_signature',
                                                      help='Extract signature for java artifact(s) or apks')
        parser_java_signature.add_argument("arg", nargs='+', help="Path to java artifact(s) and the input type")
        parser_java_signature.add_argument("-d", "--dump", default=False, action='store_true', help="Dump all features")

        # ApkSearching sub-command
        parser_apk_search = subparsers.add_parser('apk_search', help='Match apk(s) to repo(s) and java artifacts(s)')
        parser_apk_search.add_argument("-d", "--dump", default=False, action='store_true', help="Dump all features")
        parser_apk_search.add_argument("arg", help="Path to apk file(s) or apk name(s) list")

        # ApkExtract sub-command
        parser_apk_extract = subparsers.add_parser('apk_extract', help='Extract components(so, dex) from apks')
        parser_apk_extract.add_argument("arg", help="Path to apk file(s) or apk name(s) list")

        # FeatureCounting sub-command
        parser_feature_count = subparsers.add_parser('feature_count',
                                                     help='Count feature(s) to see the distribution of features')
        parser_feature_count.add_argument("arg", help="Path to feature csv or feature csv lists")

        # Validate sub-command
        parser_validate = subparsers.add_parser('validate', help='Validate if an app is open-source or not!')
        parser_validate.add_argument("arg", help="Path to the list of apps to validate!")

        # Dump sub-command
        parser_dump = subparsers.add_parser('dump', help='dump repo(s)/lib(s)')
        subparser_dump = parser_dump.add_subparsers(help='Command (strs, strs-freq-dist, repo-freq-dist)', dest='arg')
        subparser_dump.add_parser('strs', help='Dump hashed strings along with repo identifiers')
        subparser_dump.add_parser('strs-freq-dist', help='Dump frequency distribution of strings across repos')
        subparser_dump.add_parser('repo-freq-dist', help='Dump frequency distribution of strings per repo')
        subparser_dump.add_parser('repo-signs', help='Dump structural signatures of repos')

        args = parser.parse_args(argv)
        if args.cmd == "index":
            self.__mode = "Indexing"
            if args.dump and args.stats:
                pass
            if args.dump:
                self.__arg_list.append('dump')
            elif args.stats:
                self.__arg_list.append('stats')
            else:
                self.__arg_list.append(None)
        elif args.cmd == "search":
            self.__mode = "Searching"
            if args.dump and args.stats:
                pass
            if args.dump:
                self.__arg_list.append('dump')
            elif args.stats:
                self.__arg_list.append('stats')
            elif args.verbose:
                self.__arg_list.append('verbose')
            else:
                self.__arg_list.append(None)
        elif args.cmd == "signature":
            self.__mode = "Signature"
            if args.dump and args.stats:
                pass
            if args.dump:
                self.__arg_list.append('dump')
            elif args.stats:
                self.__arg_list.append('stats')
            else:
                self.__arg_list.append(None)
        elif args.cmd == "java_index":
            self.__mode = "JavaIndexing"
            if args.dump:
                self.__arg_list.append('dump')
            else:
                self.__arg_list.append(None)
        elif args.cmd == "java_search":
            self.__mode = "JavaSearching"
            if args.dump:
                self.__arg_list.append('dump')
            elif args.verbose:
                self.__arg_list.append('verbose')
            else:
                self.__arg_list.append(None)
        elif args.cmd == "java_signature":
            self.__mode = "JavaSignature"
            if args.dump:
                self.__arg_list.append('dump')
            else:
                self.__arg_list.append(None)
        elif args.cmd == "apk_search":
            self.__mode = "ApkSearching"
            if args.dump:
                self.__arg_list.append('dump')
            else:
                self.__arg_list.append(None)
        elif args.cmd == "apk_extract":
            self.__mode = "ApkExtract"
        elif args.cmd == "feature_count":
            self.__mode = "FeatureCounting"
        elif args.cmd == "validate":
            self.__mode = "Validate"
        else:
            self.__mode = "Dumping"
        self.__arg_list.append(args.arg)


if __name__ == '__main__':
    import sys

    opts = Options(sys.argv[1:])
    print opts.argv()
