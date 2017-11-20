# Constants for analysis
import os

framework_prefix = ('java', 'javax', 'org.w3c', 'org.xml', 'org.omg', 'org.ietf', 'org.apache', 'org.json', 'android', 'junit')
primitive_types = {'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double', 'void'}
object_methods = {'clone', 'equals', 'finalize', ' getClass', 'hashCode', 'notify', 'notifyAll', 'toString', 'wait', '<init>', '<clinit>'}
skip_set = {'total', 'unique', 'min_score', 'max_score', 'refcnt', 'featcnt', 'uniqfeatcnt', 'simcnt', 'classcnt',
            'uniqclasscnt', 'strcnt', 'uniqstrcnt', 'normclasscnt', 'uniqnormclasscnt',
            'centroidcnt', 'uniqcentroidcnt'}
leaf_nodes = {'strings', 'classes', 'normclasses', 'centroids'}
internal_nodes = {'files', 'dirs'}

DEVNULL = open(os.devnull, 'wb')
JAVA_SUFFIXES = ('class', 'aar', 'jar', 'dex', 'apk')
PUBLIC = 'public'
SIG_SUFFIX = '.sig'
SIG_ZIP_SUFFIX = '.sig.zip'
ZIP_SUFFIX = '.zip'
JAR_SUFFIX = '.jar'
PB_SUFFIX = '.pb'
CLASSES_JAR = 'classes.jar'
JOB_CHUNK = 100000