import tempfile
import subprocess
import os
from io import open


def get_license_info(filename=None, file_content=None, prefix='license-info-'):
    # The input is either filename or file_content
    if (filename is None or filename == '') and (file_content is None or file_content == ''):
        return []
    is_temp = False
    if file_content:
        tfile = tempfile.NamedTemporaryFile(prefix=prefix, delete=False)
        tfile = open(tfile.name, mode='wb')
        if isinstance(file_content, unicode):
            file_content = file_content.encode('utf-8')
        tfile.write(file_content)
        tfile.close()
        is_temp = True
        filename = tfile.name
    # There are three tools available, nomos, monk and ninka
    license_abbrs = get_license_abbrs(toolname='nomos', filename=filename)
    # logging.debug( 'tried nomos: %s' % license_abbrs )
    if len(license_abbrs) == 0:
        license_abbrs = get_license_abbrs('ninka', filename)
        # logging.debug( 'tried ninka: %s' % license_abbrs )
    if is_temp:
        os.remove(filename)
    return license_abbrs


def get_license_abbrs(toolname, filename):
    try:
        license_str = subprocess.check_output([toolname, filename])
        if 'no_license_found' in license_str.lower():
            # For monk and nomos
            license_abbrs = []
        elif toolname == 'ninka':
            # Produced by ninka
            license_junk_strings = {"UNKNOWN", "NONE"}
            # Get the license strings
            license_abbrs = license_str.split(';')[1].strip().split(',')
            if len(license_abbrs) == 1 and license_abbrs[0] in license_junk_strings:
                license_abbrs = []
        elif toolname == 'nomos':
            license_abbrs = license_str.split('license(s) ')[-1].strip().split(',')
        elif toolname == 'monk':
            lines = filter(bool, license_str.split('\n'))
            license_abbrs = [line.split(';')[0].split('"')[-2] for line in lines]
        else:
            raise Exception("Unknown toolname %s" % toolname)
    except:
        print toolname, filename
        license_abbrs = []
    return license_abbrs
