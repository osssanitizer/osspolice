# This script similar to extract_so_from_apks.py, but is more generic.
# This one aims at extracting specified types of files, from compressed files. It compressed files show up in the
# archive, it performs recursive extraction.
#
# The compressed file type can be: zip, bz2, gz, 7z, tar, xz, jar
# The extracted file type can be: jar, so, dex (basically compiled java and native code)
#
# The steps to detect:
# 1. If this is a folder, then print its file type
# 2. If the file is a compressed file, then inspect all of its inner files, and extract if there is a match of interest
# 3. If the inner file is compressed file, go to Step 2.

import os
import sys
import logging
import shutil
import hashlib
import types
import gflags
import magic
from multiprocessing import Pool, Manager
from compress_files import get_compressed_file, MIME_TO_ZIPTYPE_FOR_DECOMPRESSION
from tempfile import mkdtemp
from os.path import abspath, basename, relpath, realpath, dirname, splitext, exists, getsize, join
from util.job_util import getExcludeFilename, write_proto_to_file, get_fname_digest_mapping
from util.sqlite_util import SQLiteDatabase
import util.proto.repo_detail_pb2 as repo_pb

try:
    # encoding=utf8
    reload(sys)
    sys.setdefaultencoding('utf8')
except:
    pass

FLAGS = gflags.FLAGS
COMPONENTS_SUFFIX = ".components"


# Name of the summary and detail table
gflags.DEFINE_string('summary_table', 'apps_extract_summary', 'The name of the summary table')
gflags.DEFINE_string('detail_table', 'apps_extract_components_detail', 'The name of the detail table')
gflags.DEFINE_enum('store_type', 'file', ['file', 'database', 'file_with_symlink'],
                   'The type of storage to use. Database has risk condition now, donot use it')
gflags.DEFINE_string('hashdeep_basedir', None, 'The basedir for hashdeep to run on')
gflags.DEFINE_boolean('create_table_only', False, 'Only create tables, and donot do anything to update the tables')
gflags.DEFINE_integer('update_frequency', 5000, 'Update the database for 5000 apks/apps')
gflags.DEFINE_boolean('skip_processed', False, 'Skip processed = 1 apps, i.e. process only not processed ones')

# Might be useful, but not used now. Was used in previous version.
gflags.DEFINE_multistring('default_foi', ['dex', 'so', 'jar', 'zip', 'tar', 'xml', 'tgz', 'bz2', 'bzip', 'gz', 'xz'],
                          'The default file of interest. If there are too much files in a repo, '
                          'we only check these files, instead of the whole repo.')


# Utility functions
def hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()


def get_digest_and_new_filename(filepath, basedir=None, keepname=True):
    file_digest = hashfile(open(filepath, 'rb'), hashlib.sha1())
    if keepname:
        if basedir:
            relative_path = relpath(filepath, basedir)
            filename = '-'.join(filter(bool, relative_path.split('/')))
        else:
            filename = basename(filepath)
        return file_digest, '%s-%s' % (file_digest, filename)
    else:
        return file_digest, '%s%s' % (file_digest, splitext(filepath)[-1])


def get_desc_for_file(filepath):
    filepath = abspath(filepath)
    return magic.from_file(filepath)


def get_mime_for_file(filepath):
    return magic.from_file(filepath, mime=True)


def get_mime_for_repo(repo_dir):
    repo_dir = abspath(repo_dir)
    file_mime_dict = {}
    for root, dirs, files in os.walk(repo_dir):
        for name in files:
            try:
                filepath = os.path.join(root, name)
                file_mime_dict[filepath] = get_mime_for_file(filepath)
            except Exception as e:
                logging.error(
                    "Error get_mime_for_repo for %s, probably due to symbolic link (real errmsg: %s)" % (filepath, e))
    return file_mime_dict


def handle_database_main(filelist, dbpath):
    assert FLAGS.hashdeep_basedir  # This is used for performance reason
    hashdeep_basedir = abspath(FLAGS.hashdeep_basedir)
    all_fname_digest_dict = get_fname_digest_mapping(
        inpath=hashdeep_basedir, alg='sha1',
        savepath=os.path.join(dirname(hashdeep_basedir),
                              basename(hashdeep_basedir) + '.save.digest'), processes=FLAGS.process_count)
    fname_digest_dict = {}
    for fname in filelist:
        abs_fname = abspath(fname)
        if abs_fname in all_fname_digest_dict:
            fname_digest_dict[fname] = all_fname_digest_dict[abs_fname]

    # Generator for iterating filelist
    def get_column_value_generator(fname_digest_dict, source='google-play'):
        if source == 'google-play':
            for (filename, file_digest) in fname_digest_dict.items():
                # digest
                result = splitext(basename(filename))[0].rsplit('-', 1)
                if len(result) == 1:
                    package_name = result[0]
                    version = '1'
                elif len(result) == 2:
                    package_name, version = result
                else:
                    raise Exception("Uexpected input format for google play app filename! %s" % filename)
                downloaded = 1
                downloaded_path = abspath(filename)
                yield [file_digest, package_name, version, source, downloaded, downloaded_path]
        elif source == 'f-droid':
            # Generator for iterating tar.gz list
            for (filename, file_digest) in fname_digest_dict.items():
                # digest
                downloaded = 1
                downloaded_path = abspath(filename)
                yield [file_digest, source, downloaded, downloaded_path]
        else:
            raise Exception("Unhandled source %s" % source)

    # If the database is not created, create it.
    sqlite_db = SQLiteDatabase(dbpath)
    if not sqlite_db.has_connection():
        msg = "Creating database %s " % dbpath
        logging.info(msg)
        print (msg)
        if FLAGS.job == 'batch_extract' and FLAGS.sub_in_type == 'APK':
            # Extract stuff from Google Play apks, initialize the database.
            sqlite_db.create_table(table_name=FLAGS.summary_table,
                                   column_type_dict={
                                       'id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
                                       'app_digest': 'VARCHAR(100) NOT NULL UNIQUE',
                                       'package_name': 'VARCHAR(100)',  # Get this information from the filename
                                       'version': 'VARCHAR(20)',  # Get this information from the filename
                                       'source': 'VARCHAR(20)',
                                       'downloaded': 'INTEGER DEFAULT 0',
                                       'downloaded_path': 'VARCHAR(100)',
                                       'processed': 'INTEGER DEFAULT 0',
                                       'sharedlib_count': 'INTEGER',
                                   })
            sqlite_db.create_table(table_name=FLAGS.detail_table,
                                   column_type_dict={
                                       'id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
                                       'app_digest': 'VARCHAR(100)',
                                       'component_digest': 'VARCHAR(100) NOT NULL',
                                       'component_inner_path': 'VARCHAR(100)',  # 'VARCHAR(100) NOT NULL',
                                       'component_store_path': 'VARCHAR(100)',  # 'VARCHAR(100) NOT NULL',
                                       #  so, dex, jar, xml, js etc
                                       'component_type': 'VARCHAR(20)',  # 'VARCHAR(20) NOT NULL'
                                       'FOREIGN KEY(app_digest)': 'REFERENCES %s(app_digest)' % FLAGS.summary_table,
                                   })
            sqlite_db.insert_table_multirow(
                table_name=FLAGS.detail_table,
                column_name_list=['app_digest', 'package_name', 'version', 'source', 'downloaded', 'downloaded_path'],
                column_value_lists=get_column_value_generator(fname_digest_dict=fname_digest_dict,
                                                              source='google-play'))
            sqlite_db.disconnect()
        elif FLAGS.job == 'batch_extract' and FLAGS.sub_in_type == 'COMPRESSED':
            # Extract stuff from Fdroid tarballs, initialize the database.
            sqlite_db.create_table(table_name=FLAGS.summary_table,
                                   column_type_dict={
                                       'id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
                                       'app_digest': 'VARCHAR(100) NOT NULL UNIQUE',
                                       'package_name': 'VARCHAR(100)',  # Get this information from the filename
                                       'version': 'VARCHAR(20)',  # Get this information from the filename
                                       'source': 'VARCHAR(20)',
                                       'downloaded': 'INTEGER DEFAULT 0',
                                       'downloaded_path': 'VARCHAR(100)',
                                       'processed': 'INTEGER DEFAULT 0',
                                       'sharedlib_count': 'INTEGER',
                                   })
            sqlite_db.create_table(table_name=FLAGS.detail_table,
                                   column_type_dict={
                                       'id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
                                       'app_digest': 'VARCHAR(100)',
                                       'component_digest': 'VARCHAR(100) NOT NULL',
                                       'component_store_path': 'VARCHAR(100)',
                                       'component_inner_paths': 'VARCHAR(100)',
                                        # get this from extract_config.all_in_paths
                                       'component_type': 'VARCHAR(20)',  # so, dex, jar, xml, js etc
                                       'FOREIGN KEY(app_digest)': 'REFERENCES %s(app_digest)' % FLAGS.summary_table,
                                       # TODO: 'CONSTRAINT app_comp_unique': 'UNIQUE (app_digest, component_digest)'
                                   })
            sqlite_db.insert_table_multirow(
                table_name=FLAGS.summary_table,
                column_name_list=['app_digest', 'source', 'downloaded', 'downloaded_path'],
                column_value_lists=get_column_value_generator(fname_digest_dict=fname_digest_dict, source='f-droid'))
            sqlite_db.disconnect()
        else:
            # TODO: how to handle other tables
            raise Exception("Database creation not supported for job=%s, in_type=%s and sub_in_type=%s yet!" %
                            (FLAGS.job, FLAGS.in_type, FLAGS.sub_in_type))
    else:
        logging.info("Database connect SUCCESSFUL!")


# Handling different format files
# Used for extracting stuff, maps mime to file type or callback filter function, the callback should take just the
# filename as parameter and return the type of input, indicating the desired operation for current item.
def handle_zip(filename):
    filename = filename.lower()
    if filename.endswith(('.zip', '.aar', '.zap')):
        return repo_pb.COMPRESSED
    elif filename.endswith('.jar'):
        return repo_pb.JAR
    elif filename.endswith('.apk'):
        return repo_pb.APK
    else:
        return repo_pb.UNKNOWN_GOOD


def handle_jar(filename):
    filename = filename.lower()
    if filename.endswith('.apk'):
        return repo_pb.APK
    elif filename.endswith('.jar'):
        return repo_pb.JAR
    elif filename.endswith('.ogg'):
        return repo_pb.UNKNOWN_GOOD
    else:
        return repo_pb.UNKNOWN


def handle_octet_stream(filename):
    desc = get_desc_for_file(filename)
    if 'dalvik dex' in desc.lower():
        return repo_pb.DEX
    elif filename.endswith('.xml'):
        return repo_pb.XML
    elif filename.endswith('.so'):
        return repo_pb.SO
    else:
        return repo_pb.UNKNOWN_GOOD


# TODO: find a central space that lists the mime types for files
MIME_TO_FILETYPE_FOR_EXTRACTION = {
    # Recursively analyze these files
    'application/x-tar': repo_pb.COMPRESSED,
    'application/tar': repo_pb.COMPRESSED,
    'application/x-gzip': repo_pb.COMPRESSED,
    'application/gzip': repo_pb.COMPRESSED,
    'application/x-bzip2': repo_pb.COMPRESSED,
    'application/zip': handle_zip,  # This can be jar, zip, apk
    # More compressed files to add
    'application/octet-stream': handle_octet_stream,
    'application/jar': handle_jar,
    'application/java-archive': handle_jar,
    # Shared libraries
    'application/x-sharedlib': repo_pb.SO,
    'application/sharedlib': repo_pb.SO,
    # The xml files can be useful for callback analysis
    'application/xml': repo_pb.XML,
}


def get_is_first_level(extract_config, summarize_size=False):
    # To decide root level: suppose the input is an apk, it will only be unzipped once and then the result is the root
    # level. We only need summary for Android apps, and we don't need for tar.gz etc.
    if len(extract_config.all_in_paths) == 0:
        if summarize_size and not extract_config.in_type in (repo_pb.APK, repo_pb.DEX):
            raise Exception('The input type for summarize_size functionality can only be APK/DEX, but specified %s' %
                            repo_pb.FileType.Name(extract_config.in_type))
        return True
    else:
        return False


def extract_from_repo(indir, outdir, extract_config, component_digest_set=None, new_component_digest_set=None,
                      summarize_size=False):
    # indir, outdir, extract_types, inspect_compressed_files
    file_mime_dict = get_mime_for_repo(indir)  # TODO: the filename encoding problem is handled here.
    extract_type_set = set([t for t in extract_config.extract_types])

    # only used if summarize_size is True
    is_first_level = get_is_first_level(extract_config=extract_config, summarize_size=summarize_size)
    mime2size = {}
    suffix2size = {}
    dir2size = {}
    for filepath in file_mime_dict:
        if summarize_size and is_first_level:
            # Summarize the size based on mimes, suffixes and dirs, only if we are processing at the root level
            filesize = getsize(filepath)
            filemime = file_mime_dict[filepath]
            filesuffix = splitext(filepath)[-1]  # some files may not have suffixes
            filedir = relpath(dirname(filepath), indir)

            # 1. mimes
            mime2size.setdefault(filemime, 0)
            mime2size[filemime] += filesize
            # 2. suffixes
            suffix2size.setdefault(filesuffix, 0)
            suffix2size[filesuffix] += filesize
            # 3. dirs
            dir2size.setdefault(filedir, 0)
            dir2size[filedir] += filesize

        if file_mime_dict[filepath] in MIME_TO_FILETYPE_FOR_EXTRACTION:
            # Get different operations for different types of files
            logging.info('found (file: %s, type: %s) for extraction', filepath, file_mime_dict[filepath])
            file_type = MIME_TO_FILETYPE_FOR_EXTRACTION[file_mime_dict[filepath]]
            if isinstance(file_type, types.FunctionType):
                file_type = file_type(filepath)
                if file_type == repo_pb.UNKNOWN:
                    logging.error("unknown file_type for: %s, mime-type %s" % (filepath, file_mime_dict[filepath]))
                elif file_type == repo_pb.UNKNOWN_GOOD:
                    # '.cards', '.xps', '.svn-base', '.ap_'
                    logging.info("unknown_good file_type for: %s, mime-type %s" % (filepath, file_mime_dict[filepath]))

            ###########################################################################
            # Type 1: compressed files -- inspect compressed file recursively
            ###########################################################################
            if (extract_config.inspect_compressed_files and file_type not in extract_config.extract_types and
                        file_type in (repo_pb.COMPRESSED, repo_pb.APK)):
                # The in_paths is the relative path
                relpath_indir = relpath(filepath, indir)
                extract_config.all_in_paths.append(
                    relpath_indir.encode('utf8') if isinstance(relpath_indir, unicode) else relpath_indir)

                # Recursively update the in path and in type, change and restore the input variables.
                (save_in_path, save_in_type) = (extract_config.in_path, extract_config.in_type)
                (extract_config.in_path, extract_config.in_type) = (
                filepath.encode('utf8') if isinstance(filepath, unicode) else filepath, file_type)
                extract_from_file_or_repo(extract_config, component_digest_set=component_digest_set,
                                          new_component_digest_set=new_component_digest_set)  # Do the job
                (extract_config.in_path, extract_config.in_type) = (save_in_path, save_in_type)
                del extract_config.all_in_paths[-1]
            # End Type 1

            ###########################################################################
            # Type 2: extract files -- simply extract them
            ###########################################################################
            if file_type in extract_type_set:
                # The in_paths is the relative path
                relpath_indir = relpath(filepath, indir)
                extract_config.all_in_paths.append(
                    relpath_indir.encode('utf8') if isinstance(relpath_indir, unicode) else relpath_indir)

                """For a qualified file
                # Step 1: Check whether this file is already extracted, if so, just update database, o.w. goto Step 2
                # Step 2: Extract the file to specified path, and update database
                """
                logging.info("found a interested: type - %s, doc - %s" % (file_type, filepath))
                file_digest, new_filename = get_digest_and_new_filename(filepath, basedir=indir, keepname=True)
                if extract_config.store_type == 'database':
                    raise Exception("Deprecated")

                elif extract_config.store_type == 'file':
                    extract_component = extract_config.components.add()
                    if file_digest in component_digest_set:
                        print ("Already extracted, skipping store path")
                    else:
                        # Extract the necessary files and name them appropriately.
                        print ("extracting %s to out folder %s" % (new_filename, outdir))
                        storepath = join(outdir, new_filename)
                        shutil.copyfile(filepath, storepath)
                        extract_component.store_path = storepath.encode('utf8') if isinstance(storepath,
                                                                                              unicode) else storepath
                        component_digest_set[file_digest] = True
                        new_component_digest_set[file_digest] = True
                    extract_component.component_digest = file_digest
                    extract_component.component_inner_paths.extend(extract_config.all_in_paths)
                    extract_component.component_type = file_type
                    # Restore original all_in_paths
                    del extract_config.all_in_paths[-1]

                elif extract_config.store_type == 'file_with_symlink':
                    extract_component = extract_config.components.add()
                    # symbolic link is used to deduplicate!
                    expected_symbol_link = join(outdir, file_digest)
                    if exists(expected_symbol_link):
                        print ("Already extracted, reusing symbolic path for file digest: %s" % file_digest)
                        extract_component.store_path = realpath(expected_symbol_link)
                    else:
                        # Extract the necessary files and name them approapriately!
                        print ("extracting %s to out folder %s and creating symbol links" % (new_filename, outdir))
                        storepath = join(outdir, new_filename)
                        shutil.copyfile(filepath, storepath)
                        extract_component.store_path = storepath.encode('utf8') if isinstance(storepath,
                                                                                              unicode) else storepath
                        try:
                            os.symlink(storepath, expected_symbol_link)
                        except OSError as e:
                            msg = "OSError when creating %s: %s", expected_symbol_link, str(e)
                            print (msg)
                            logging.error(msg)

                    extract_component.component_digest = file_digest
                    extract_component.component_inner_paths.extend(extract_config.all_in_paths)
                    extract_component.component_type = file_type
                    # Restore original all_in_paths
                    del extract_config.all_in_paths[-1]

                else:
                    raise Exception("Unhandled store type: %s" % extract_config.store_type)
                    # End Type 2

        else:
            # logging.error("unknown mime type %s" % file_mime_dict[filepath])
            # logging.debug("unknown or not interesting mime type %s" % file_mime_dict[filepath])
            pass

    if summarize_size and is_first_level:
        for mime, size in mime2size.items():
            label_size = extract_config.mime_based_sizes.add()
            label_size.label = mime
            label_size.size = size
        for suffix, size in suffix2size.items():
            label_size = extract_config.suffix_based_sizes.add()
            label_size.label = suffix
            label_size.size = size
        for folder, size in dir2size.items():
            label_size = extract_config.dir_based_sizes.add()
            label_size.label = folder
            label_size.size = size
        extract_config.app_size = getsize(extract_config.in_path)
        extract_config.unpacked_size = sum(mime2size.values())

    logging.debug("extract_from_repo successfully complete")


########################################################################
# The main entry for extractor
########################################################################
def extract_from_file_or_repo(extract_config, component_digest_set=None, new_component_digest_set=None,
                              summarize_size=False):
    """Check for the input type vs. input path. If input is compressed file, decompress it to dir. For dir input or
    decompressed dir, extract extract_types to specified outdir.

    :param extract_config: the configuration
    """
    # NOTE: We will *not* be extracting from *normal* files!
    try:
        extract_dir = None
        is_temp = False

        # Set extract_dir, decompress files if the input file is compressed file.
        if (extract_config.in_type not in extract_config.extract_types and extract_config.in_type in (
        repo_pb.COMPRESSED, repo_pb.APK)):
            logging.debug("get_compressed_file: %s" % extract_config.in_path)
            file_with_meta = get_compressed_file(extract_config.in_path)
            if file_with_meta is None:
                logging.debug('%s: get_compressed_file failed, trying get_mime_for_file for decompression!' %
                              extract_config.in_path)
                file_mime = get_mime_for_file(extract_config.in_path)
                if file_mime in MIME_TO_ZIPTYPE_FOR_DECOMPRESSION:
                    file_with_meta = MIME_TO_ZIPTYPE_FOR_DECOMPRESSION[file_mime](extract_config.in_path)
                else:
                    logging.error("Unknown compressed input format! - %s" % file_mime)
                    # no need to continue
                    return

            file_obj = file_with_meta.accessor
            extract_dir = mkdtemp(prefix='get-mime-')
            is_temp = True
            if hasattr(file_obj, 'extractall'):
                file_obj.extractall(extract_dir)
            else:
                if file_with_meta.file_type in ('gz', 'bz2'):
                    temp_filename = os.path.join(extract_dir, splitext(basename(extract_config.in_path))[0])
                    try:
                        open(temp_filename, 'w').write(file_obj.read())
                    except IOError as ioe:
                        msg = "Error extracting %s: %s" % (extract_config.in_path, ioe)
                        logging.error(msg)
                        print (msg)
                else:
                    logging.error('Unhandled compressed file format: %s' % file_with_meta.file_type)
        elif extract_config.in_type == repo_pb.DIR:
            extract_dir = extract_config.in_path
        else:
            # This shouldn't happen
            raise Exception("Unhandled type of input: %s" % extract_config.in_type)
        if not exists(extract_config.out_path):
            os.makedirs(extract_config.out_path)

        # Start extraction
        extract_from_repo(indir=extract_dir, outdir=extract_config.out_path, extract_config=extract_config,
                          component_digest_set=component_digest_set, new_component_digest_set=new_component_digest_set)
        # Clean up
        if is_temp:
            shutil.rmtree(extract_dir)

        # Job succeeded
        exclude_file = getExcludeFilename(prefix='finish')
        if exclude_file:
            open(exclude_file, 'a').write('%s\n' % (extract_config.in_path))
    except OSError:
        logging.error("Processing %s" % (extract_config.in_path))
        exclude_file = getExcludeFilename(prefix='finish')
        if exclude_file:
            open(exclude_file, 'a').write('%s\n' % (extract_config.in_path))
    except UnicodeEncodeError:
        logging.error("Processing %s, with UnicodeEncodeError" % (extract_config.in_path))
        exclude_file = getExcludeFilename(prefix='finish')
        if exclude_file:
            open(exclude_file, 'a').write('%s\n' % (extract_config.in_path))
    except Exception as e:
        # Job failed
        logging.error("Processing %s, with Error %s, extract_config:\n%s" % (extract_config.in_path, e, extract_config))
        exclude_file = getExcludeFilename(prefix='finish')
        if exclude_file:
            open(exclude_file, 'a').write('%s\n' % (extract_config.in_path))
        print("Unexpected error: ", str(e))


########################################################################
# This function is used by celery workers!
########################################################################
def run_extractor_worker(infile, outdir, extract_types=['SO'], in_type='APK', store_type="file_with_symlink'",
                         skip_processed=False, binary=False):
    # 1. extract the dex/so files, and store them to outdir. For each file, create a symbolic link using hash
    #   (used for deduplication)
    # 2. also store the ".components" file to the outdir
    logging.info("Processing %s" % infile)

    if skip_processed and exists(join(outdir, infile + COMPONENTS_SUFFIX)):
        logging.info("Skipping processed infile %s", infile)
        return

    extract_config = repo_pb.ExtractConfig()
    for extract_type in extract_types:
        extract_config.extract_types.append(getattr(repo_pb, extract_type))
    file_digest = hashfile(open(infile, 'rb'), hashlib.sha1())
    extract_config.inspect_compressed_files = True
    extract_config.in_path = infile.encode('utf8') if isinstance(infile, unicode) else infile
    extract_config.in_digest = file_digest
    extract_config.store_type = store_type
    extract_config.in_type = getattr(repo_pb, in_type)
    extract_config.out_path = outdir.encode('utf8') if isinstance(outdir, unicode) else outdir

    # extract types of files from infile, use symbol links for deduplication!
    extract_from_file_or_repo(extract_config=extract_config)
    outfile = join(extract_config.out_path, basename((extract_config.in_path)) + COMPONENTS_SUFFIX)
    write_proto_to_file(proto=extract_config, filename=outfile, binary=binary)
    logging.info("extracted %d components from %s, and saved output to %s", len(extract_config.components), infile,
                 outfile)
    return outfile


########################################################################
# Wrapper around extract_from_file_or_repo, for parallelization
########################################################################
def secure_extract_from_file_or_repo(tuple_input):
    inpath, app_digest_set, component_digest_set, new_component_digest_set = tuple_input
    """A wrapper around extract_from_file_or_repo, simply configures the extract configuration

    :param inpath: input path specified by command line
    :param app_digest_set: all the app digest
    :param component_digest_set: all the component digest
    """
    msg = "Processing %s" % inpath
    logging.info(msg)
    print(msg)
    extract_config = repo_pb.ExtractConfig()
    for extract_type in FLAGS.extract_types:
        extract_config.extract_types.append(getattr(repo_pb, extract_type))
    if FLAGS.dbfile:
        extract_config.db_path = FLAGS.dbfile
    file_digest = hashfile(open(inpath, 'rb'), hashlib.sha1()) if os.path.isfile(inpath) else None
    extract_config.inspect_compressed_files = True
    extract_config.in_path = inpath.encode('utf8') if isinstance(inpath, unicode) else inpath
    extract_config.in_digest = file_digest
    extract_config.store_type = FLAGS.store_type
    # sub_in_type is the input type for workers
    extract_config.in_type = getattr(repo_pb, FLAGS.sub_in_type)
    # outpath is generic for all files, and files are named with digests
    extract_config.out_path = FLAGS.outdir.encode('utf8') if isinstance(FLAGS.outdir, unicode) else FLAGS.outdir

    if extract_config.store_type == 'database':
        # Store using database.
        raise Exception("deprecated")
        # extract_config.summary_table_name = FLAGS.summary_table
        # extract_config.detail_table_name = FLAGS.detail_table
        # db_obj_for_summary = SQLiteDatabase(dbpath=FLAGS.dbfile)
        # processed = db_obj_for_summary.exists_table(table_name=FLAGS.summary_table,
        #                                             where_name_value_dict={'app_digest': file_digest, 'processed': 1})
        # if not processed:
        #     try:
        #         extract_from_file_or_repo(extract_config)
        #         db_obj_for_summary.update_table(table_name=FLAGS.summary_table,
        #                                         # TODO: sharedlib_count is non-trivial to get, skipping for now!
        #                                         set_name_value_dict={'processed': 1},
        #                                         where_name_value_dict={'app_digest': file_digest})
        #     except Exception as e:
        #         db_obj_for_summary.update_table(table_name=FLAGS.summary_table,
        #                                         # 0, non-processed, 1, processed, -1, error processing
        #                                         set_name_value_dict={'processed': -1},
        #                                         where_name_value_dict={'app_digest': file_digest})
        #         msg = "Error processing %s: %s" % (inpath, e)
        #         logging.error(msg)
        #         print (msg)
    elif extract_config.store_type == 'file':
        if file_digest not in app_digest_set:  # not processed
            extract_from_file_or_repo(extract_config=extract_config,
                                      component_digest_set=component_digest_set,
                                      new_component_digest_set=new_component_digest_set,
                                      summarize_size=FLAGS.summarize_size)
            app_digest_set[file_digest] = True
            if len(extract_config.components) > 0:  # Something was extracted
                write_proto_to_file(proto=extract_config, filename=os.path.join(
                    extract_config.out_path, basename((extract_config.in_path)) + COMPONENTS_SUFFIX), binary=False)
                logging.debug("%s write analyzed components to file successful, extract_config:\n%s" % (
                extract_config.in_path, extract_config))
            else:
                logging.info("No extracted components:%s" % extract_config)
        else:
            logging.info("Skipping processed item: %s" % inpath)
    else:
        # file_with_symlink is not used here!
        raise Exception("Unhandled store type")


########################################################################
# Extract files in batch, using multiprocessing module
########################################################################
def batch_extract(filelist):
    """Parallel the secure_extract_from_file_or_repo job.

    :param filelist: the list of input files
    """
    if FLAGS.dbfile and not exists(FLAGS.dbfile):
        msg = "Initializing the database for processing %d items....." % len(filelist)
        logging.info(msg)
        print (msg)
        handle_database_main(filelist=filelist, dbpath=FLAGS.dbfile)
    if FLAGS.create_table_only:
        return

    # at this time, the database should be there
    if FLAGS.dbfile:
        db_obj = SQLiteDatabase(dbpath=FLAGS.dbfile)

        # get processed digests
        if FLAGS.skip_processed:  # the processed apps
            all_app_digests = db_obj.query_table(table_name=FLAGS.summary_table, select_name_list=['app_digest'],
                                                 where_name_value_dict={'processed': 1}, fetchone=False)
        all_component_digests = db_obj.query_table(table_name=FLAGS.detail_table, select_name_list=['component_digest'],
                                                   where_name_value_dict=None, fetchone=False)
    else:
        # TODO: No dbfile branch. The implementation needs to be double checked.
        if FLAGS.skip_processed:
            all_app_digests = []
        all_component_digests = []

    m = Manager()
    # the digest of apps, the digest of components
    app_digest_set = m.dict()
    if FLAGS.skip_processed:  # the processed apps
        for app_digest in all_app_digests:
            app_digest = app_digest[0]
            app_digest_set[app_digest] = False
    component_digest_set = m.dict()
    for comp_digest in all_component_digests:
        comp_digest = comp_digest[0]
        component_digest_set[comp_digest] = False

    msg = "There are %d file or repos to extract!" % len(filelist)
    logging.info(msg)
    print(msg)
    # TODO: very ad-hoc manner for skipping processed jobs.
    processed_count = len(app_digest_set)
    for start in range(processed_count, len(filelist),
                       FLAGS.update_frequency):  # range(0, len(filelist), FLAGS.update_frequency):
        end = min(start + FLAGS.update_frequency, len(filelist))
        sub_filelist = filelist[start: end]
        sub_msg = "Processing %d file or repos!" % len(sub_filelist)
        logging.info(sub_msg)
        app_digest_set = m.dict()
        new_component_digest_set = m.dict()

        pool = Pool(processes=FLAGS.process_count)
        # The original version that have database race conditions
        # pool.map(secure_extract_from_file_or_repo, filelist)
        tuple_input = []
        for filename in sub_filelist:
            tuple_input.append((filename, app_digest_set, component_digest_set, new_component_digest_set))
        pool.map(func=secure_extract_from_file_or_repo, iterable=tuple_input)
        pool.close()
        pool.join()

        # store new digests
        logging.info("storing results")
        for app_digest, is_new in app_digest_set.items():
            if is_new:
                if FLAGS.dbfile:
                    db_obj.update_table(table_name=FLAGS.summary_table, set_name_value_dict={'processed': 1},
                                        where_name_value_dict={'app_digest': app_digest})
                app_digest_set[app_digest] = False
            else:
                pass
                # logging.info("skipping processed %s" % app_digest)
                # How about apps that we fail to process?
                #
                # print ("failure on %s" % app_digest)
                # db_obj.update_table(table_name=FLAGS.summary_table, set_name_value_dict={'processed': -1},
                #                    where_name_value_dict={'app_digest': app_digest})
        new_components_lists = [[new_digest] for new_digest in new_component_digest_set.keys()]
        if len(new_components_lists) > 0:
            if FLAGS.dbfile:
                db_obj.insert_table_multirow(table_name=FLAGS.detail_table, column_name_list=['component_digest'],
                                             column_value_lists=new_components_lists)
            for new_components in new_components_lists:
                new_component_digest = new_components[0]
                component_digest_set[new_component_digest] = False
