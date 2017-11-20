#!/usr/bin/python

#################################################################
# Configuration parser
#################################################################
class Config():
    __configParser = None

    def __init__(self, file_path="config"):
        try:
            import ConfigParser
            self.__configParser = ConfigParser.RawConfigParser()
            self.__configParser.read(file_path)

        except ImportError as ie:
            raise Exception("ConfigParser module not available. Please install")

        except Exception as e:
            raise Exception("Error parsing " + file_path + ": " + str(e))

    def get(self, opt, sec="Main"):
        if not self.__configParser:
            return None
        try:
            return self.__configParser.get(sec, opt)
        except Exception as e:
            #raise Exception("Error getting config for " + \
            #                    sec + " :" + cfg + ": " + str(e))
            return None
