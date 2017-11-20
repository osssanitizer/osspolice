import redisclient
import config as appconfig
import logger as applogger
import pandas as pd
import numpy as np
import json
import re, os, sys
from os.path import dirname, join

from itertools import izip
from functools import partial
from ast import literal_eval as make_tuple
from pandas.util.testing import assert_frame_equal
from random import randint, shuffle
from datetime import date
from bokeh.layouts import row, column, widgetbox
from bokeh.charts import Line, Bar
from bokeh.charts.operations import blend
from bokeh.models import Button, ColumnDataSource, Callback, CustomJS
from bokeh.models.widgets import Slider, DatePicker, Select, TextInput
from bokeh.models.widgets.tables import NumberFormatter
from bokeh.models.widgets.tables import HTMLTemplateFormatter
from bokeh.models.widgets import DataTable, TableColumn, Select, Slider
from bokeh.models.widgets.tables import SelectEditor, TextEditor
from bokeh.plotting import curdoc

###########################################################
# Viewer
###########################################################
class Viewer(object):

    def __init__(self, config_path='config'):
        config = appconfig.Config(file_path=config_path)
        if not config:
            exit(1)

        # logging infrastructure
        logfile_prefix = config.get("LOGFILE_PREFIX", "Viewer")
        try:
            logger = applogger.Logger("Viewer", logfile_prefix).get()
        except Exception as e:
            print ("Error setting up 'Viewer' logger: %s" % str(e))
            exit(1)

        self.config = config
        self.logger = logger
        self.selected_data = []

        # the app name database
        app_info = config.get("APP_INFO", "Viewer")
        if not app_info or app_info == "Disabled":
            self.app_info = None
        else:
            # TODO: load app database
            self.app_info = app_info

        # check for result db
        result_db = config.get("RESULT_DB", "Infrastructure")
        if not result_db:
            logger.error("Result db missing from config")
            exit(1)
        elif result_db != "Redis":
            logger.error("Unsupported RESULT_DB type: %s", result_db)
            exit(1)
        else:
            # check if redis is working
            try:
                import redisclient
                self.rrc = redisclient.RedisClient(config, "RESULT")
            except Exception as e:
                logger.error("Error setting up redis: %s", str(e))
                exit(1)

        # redis client handle
        if self.rrc and not self.rrc.handle():
            logger.error("Result redis client not available! Exiting.")
            exit(1)

        ###########################################################
        # Repos
        ###########################################################
        repo_src = config.get("REPO_SOURCE", "Infrastructure")
        if repo_src:
            repo_url_proto = config.get("REPO_URL_PROTOCOL", repo_src)
            repo_url_hostname = config.get("REPO_URL_HOSTNAME", repo_src)
            if repo_url_proto and repo_url_hostname:
                self.REPO_SOURCE = repo_src
                self.REPO_URL_PROTOCOL = repo_url_proto
                self.REPO_URL_HOSTNAME = repo_url_hostname
                self.REPO_URL = self.REPO_URL_PROTOCOL + "://" + self.REPO_URL_HOSTNAME
            else:
                logger.error("REPO_URL_PROTOCOL or REPO_URL_HOSTNAME (" + repo_src + ") missing from config")
                exit(1)
        else:
            logger.error("No REPO_SOURCE found in config")
            exit(1)

        # TODO: maybe load OSS_DB?

        # The skip set for loading data
        self.skip_set = set(['repo_matches', 'package_name', 'app_path', 'app_count', 'decision', 'status', 'comment'])


    ###########################################################
    # Load data
    ###########################################################
    #def get_data(self, match="*.apk", maxcount=10000):
    def get_data(self, match=None, start=0, maxcount=10000):
        # path -> [(software id, featfreq, featcnt) -> score, ...]
        redis = self.rrc.handle()
        all_keys = redis.keys() if not match else redis.keys(pattern=match)
        # XXX, Hack
        if maxcount:
            #shuffle(all_keys)
            all_keys = sorted(all_keys)
            all_keys = all_keys[start:maxcount]

        rrc_pipe = self.rrc.pipeline()
        for key in all_keys:
            rrc_pipe.hget(key, 'repo_matches')
        all_matches_count = rrc_pipe.execute()
        matched_keys = []
        for key, matches_count in izip(all_keys, all_matches_count):
            if matches_count is None:
                 self.rrc.handle().delete(key)
                 continue
            matches_count = int(matches_count)
            if matches_count > 0:
                matched_keys.append(key)
                rrc_pipe.hgetall(key)

        # the matched paths
        all_matches_detail = rrc_pipe.execute()
        self._redis_data = {}
        self._data = {}
        myindex = 0
        for key, results in izip(matched_keys, all_matches_detail):
            self._redis_data.setdefault(key, {})
            decision = "Unprocessed"; status = "Unprocessed"; comment = ""
            for info, score in results.items():
                if info in self.skip_set:
                    # package_name, app_path, app_count is stored separately in a protocol buffer file
                    if info == 'decision':
                        decision = score
                    elif info == "status":
                        status = score
                    elif info == "comment":
                        comment = score
                    else:
                        # skip label based key values
                        pass
                    continue

                # In java side, it is software_id -> version matched info
                # In native side, it is software matched info -> score
                try:
                    # if this succeeds, it is native
                    software_name = info
                    result = make_tuple(score)
                    high_score = 0; version = None
                    for r in result:
                        if r[-2] > high_score:
                            high_score = r[-2]; version = r[0]
                    high_version = ''
                    for r in result:
                        if r[-2] == high_score:
                            if len(r) == 7:
                                version, repo_id, partial_or_full, featfreq, featcnt, score, normscore = r
                            elif len(r) == 6:
                                version, repo_id, featfreq, featcnt, score, normscore = r
                                partial_or_full = 'full'
                            high_version += version
                    score = high_score; version = high_version

                except ValueError:
                    # this is java
                    software_name = info
                    partial_or_full = "full"
                    version, repo_id, featfreq, featcnt, score, normscore = make_tuple(score)
                except Exception as e:
                    self.logger.error("Unexpected key value pair (%s, %s) in name %s", info, score, key)

                # the matched information
                self._redis_data.setdefault(key, {})
                self._redis_data[key][info] = score

                path = os.path.basename(key)
                md5hash = path.split('-')[0]
                libname = path.split('-')[-1]
                software_name = re.sub('[\[\](),\'{}<>]', '', software_name)
                data_row = {'name': libname, 'path': key, 'myindex': myindex, 'repo_id': repo_id,
                            'software_name': software_name, "version": version, "partial": partial_or_full,
                            'featfreq': featfreq, 'featcnt': featcnt, 'score': score, 'normscore': normscore,
                            'decision': decision, 'status': status, 'comment': comment}
                for dk, dv in data_row.items():
                    self._data.setdefault(dk, [])
                    self._data[dk].append(dv)

                myindex += 1

        return self._data


    ###########################################################
    # Update data
    ###########################################################
    def update_display_data(self, patch_dict):
        # self.source.patch({'path': [(0, 'hello world')]})
        # self.original_source.patch({'path': [(0, 'hello world')]})
        # update data, use patch for updating specific location, use add for adding a new column
        #
        # 1. if we want to investigate new data, then we need to reload the website
        # 2. to incrementally add redis data to the graph, we should use ColumnDataSource.stream
        self.original_source.patch(patch_dict)

    def update_redis_data(self, name, key, value):
        # for a particular key, update the attributes
        self.logger.info("updating name %s, key %s, value %s", name, key, value)
        self.rrc.handle().hset(name, key, value)

    def safe_get_dataframe(self, column_data_source, filter_indexes=None):
        source_data_dict = {}
        if not filter_indexes:
            for key, values in column_data_source.data.viewitems():
                if key == 'index' or 'name':
                    continue
                source_data_dict[key] = values
        else:
            count = 0
            allowed_rows = []
            for index in column_data_source.data['myindex']:
                if index in filter_indexes:
                    allowed_rows.append(count)
                count += 1
            for key, values in column_data_source.data.viewitems():
                if key == 'index' or 'name':
                    continue
                value_list = []
                count = 0
                for value in values:
                    if count in allowed_rows:
                        value_list.append(value)
                    count += 1
                source_data_dict[key] = value_list

        return pd.DataFrame(source_data_dict), source_data_dict

    def update_source(self, file_select):
        try:
            pass
        except Exception as e:
            self.logger.error("error: %s", str(e))

    def update(self):
        try:
            new_df, new_df_dict = self.safe_get_dataframe(self.source)
            # source changed, but original source doesn't
            row_changed = len(self.source.data['path']) != len(self.original_source.data['path'])
            if row_changed:
                self.logger.debug("source has %s rows, tmp source has %s rows", len(self.source.data['path']), len(self.original_source.data['path']))
                old_df, _ = self.safe_get_dataframe(self.original_source, new_df_dict['myindex'])
            else:
                old_df, _ = self.safe_get_dataframe(self.original_source)

            new_df = new_df.sort_values(by=['myindex'], ascending=[True])
            new_df = new_df.reset_index(drop=True)
            old_df = old_df.sort_values(by=['myindex'], ascending=[True])
            old_df = old_df.reset_index(drop=True)
            assert_frame_equal(old_df, new_df)
            self.logger.debug("nothing changed!")
        except AssertionError:
            # build a mapping between id and myindex.
            id2myindex = {index: row['myindex'] for index, row in old_df.iterrows()}

            # reference link
            # http://stackoverflow.com/questions/17095101/outputting-difference-in-two-pandas-dataframes-side-by-side-highlighting-the-d
            ne_stacked = (old_df != new_df).stack()
            changed = ne_stacked[ne_stacked]
            changed.index.names = ['id', 'col']
            different_locations = np.where(old_df != new_df)
            changed_from = old_df.values[different_locations]
            changed_to = new_df.values[different_locations]
            changed_df = pd.DataFrame({'from': changed_from, 'to': changed_to}, index=changed.index)
            self.logger.debug("update data: %s", changed_df)

            # generate patch dict and redis name, key, value update queries
            patch_dict = {}
            for index, row in changed_df.iterrows():
                row_id, column_id = index
                patch_dict.setdefault(column_id, [])
                myindex = id2myindex[row_id]
                path = old_df['path'].iloc[row_id]
                patch_dict[column_id].append((myindex, row['to']))
                # self.logger.info("updating name %s, key %s, value %s (old value %s)", path, column_id, row['to'], row['from'])
                self.update_redis_data(path, column_id, row['to'])
            self.update_display_data(patch_dict)
            self.logger.info("patch dict is: %s", patch_dict)
        except Exception as e:
            self.logger.error("Unexpected error: %s", str(e))


    ###########################################################
    # Create UI
    ###########################################################
    def create_ui(self, data):
        self.logger.info("number of data items %d", len(data))

        # Create data source and data table
        # path, score, software_id, featcnt, featfreq, app name, app path, decision, status, comment, active in play, still voilating
        decision_editor = SelectEditor(options=["Unprocessed", "GPL Violation", "LGPL Violation", "Open Source App",
                                                "False Positive", "False Negative (LGPL)", "False Negative (GPL)"])
        status_editor = SelectEditor(options=["Unprocessed", "Emailed", "Confirmed", "Denied", "Authorized"])
        if self.app_info:
            columns = [
                TableColumn(field="myindex", title="Id"),
                TableColumn(field="path", title="File Path"),
                TableColumn(field="score", title="Score"),
                TableColumn(field="normscore", title="NormScore", formatter=NumberFormatter(format="0.00")),
                TableColumn(field="partial", title="PartialMatch"),
                TableColumn(field="repo_id", title="Repo ID"),
                TableColumn(field="software_name", title="OSS"),
                TableColumn(field="version", title="Version"),
                TableColumn(field="featcnt", title="FeatCount",),
                TableColumn(field="featfreq", title="FeatFreq",),
                TableColumn(field="package_name", title="Package"),
                TableColumn(field="app_path", title="App Path"),
                TableColumn(field="app_count", title="App Count"),
                TableColumn(field="decision", title="Decision", editor=decision_editor),
                TableColumn(field="status", title="Status", editor=status_editor),
                TableColumn(field="comment", title="Comment"),
                # I am not sure whether we should add these two fields here.
                # TableColumn(field="active", title="Active in Play"),
                # TableColumn(field="still_violating", title="Still Violating"),
            ]
        else:
            template_str = '<a href="' + self.REPO_URL + '/<%= value %>"><%= value %></a>'
            columns = [
                TableColumn(field="myindex", title="Id",),
                TableColumn(field="name", title="Name"),
                TableColumn(field="score", title="Score", formatter=NumberFormatter(format="0.00")),
                TableColumn(field="normscore", title="NormScore", formatter=NumberFormatter(format="0.00")),
                TableColumn(field="partial", title="PartialMatch"),
                TableColumn(field="repo_id", title="RepoID"),
                TableColumn(field="software_name", title="OSS", formatter=HTMLTemplateFormatter(template=template_str)),
                TableColumn(field="featcnt", title="FeatCount", formatter=NumberFormatter(format="0,000,000")),
                TableColumn(field="featfreq", title="FeatFreq", formatter=NumberFormatter(format="0,000,000")),
                TableColumn(field="version", title="Version"),
                TableColumn(field="decision", title="Decision", editor=decision_editor),
                TableColumn(field="status", title="Status", editor=status_editor),
                TableColumn(field="comment", title="Comment"),
                TableColumn(field="path", title="Path"),
            ]

        # source is the displayed table, and can be modified by user
        # original_source is the original data, it is the base, and can only be modified by the program
        self.source = ColumnDataSource(self._data)
        self.original_source = ColumnDataSource(self._data)
        self.data_table = DataTable(source=self.source, columns=columns, width=2000, height=2000, editable=True, sortable=True)  # Disable sortable for now!

        # selector or filters
        # reference link for callback: https://gist.github.com/dennisobrien/450d7da20daaba6d39d0
        min_matching_score_slider = Slider(start=0, end=2, value=0.3, step=.01, title="Minimum Matching Score")
        max_matching_score_slider = Slider(start=0, end=2, value=0.7, step=.01, title="Maximum Matching Score")
        featfreq_slider = Slider(start=0, end=10000, value=0, step=1, title="Minimum Matching Num of Features")
        featcnt_slider = Slider(start=0, end=10000, value=50, step=1, title="Minimum Feature Count is OSS")
        kind_select = Select(value="All", options=["All", "Java", "Native"])
        file_select = Select(value="Name", options=["Name", "MD5", "Path"])
        search_input = TextInput(value=None, title="Enter library to search", callback=None)
        search_button = Button(label="Search", button_type="success")
	
        download_callback_code = """
        var data = source.get('data');
        var filetext = 'Id,File Name,Matching Score,Normalized Matching Score,Repo ID,Software Name,Feature Count,Feature Freq.,Version,Decision,Status,Comment,File Path\\n';

        var order = ['myindex', 'name', 'score', 'normscore', 'repo_id', 'software_name', 'featcnt', 'featfreq', 'version', 'decision', 'status', 'comment', 'path'];

        for (var i = 0; i < data['path'].length; ++i) {
            var currRow = [];
            for (var item in order) {
                key = order[item]
                currRow.push(data[key][i]);
            }
            var joined = currRow.join().concat('\\n');
            filetext = filetext.concat(joined);
        }

        var filename = 'violations.csv';
        var blob = new Blob([filetext], { type: 'text/csv;charset=utf-8;' });
        
        //addresses IE
        if (navigator.msSaveBlob) {
            //navigator.msSaveBlob(blob, filename);
        }
        else {
            var link = document.createElement("a");
            link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.target = "_blank";
            link.style.visibility = 'hidden';
            link.dispatchEvent(new MouseEvent('click'));
        }
        """

        # enable downloading of results as a csv file
        download_button = Button(label="Download", button_type="success")
        download_button.callback = CustomJS(
            args=dict(source=self.source), code=download_callback_code
        )

        # enable comparison of selected rows
        compare_button = Button(label="Compare", button_type="success")
        compare_button.on_click(self.compare_callback)

        # update on change
        #controls = [min_matching_score_slider, max_matching_score_slider, featfreq_slider, \
        #            featcnt_slider, kind_select, file_select, button]
        #for item in controls:
        #    item.on_change('value', lambda attr, old, new: self.update_source(item))

        combined_callback_code = """
        var data = source.get('data');
        var original_data = original_source.get('data');
        var min_score = min_matching_score_slider.get('value');
        var max_score = max_matching_score_slider.get('value');
        var search_input = search_input.get('value');
        var min_featfreq = featfreq_slider.get('value');
        var min_featcnt = featcnt_slider.get('value');
        var kind = kind_select.get('value');
        console.log("min score: " + min_score + ", max score: " + max_score + ", min_featfreq: " + min_featfreq + ", min_featcnt" + min_featcnt + ", kind" + kind);
        var java_suffix = ".dex";
        var native_suffix = ".so";

        console.log("searchinput: " + search_input);
        var re;
        if (search_input) {
            re = new RegExp(search_input);
        } else {
            re = new RegExp(".*");
        }

        for (var key in original_data) {
            data[key] = [];
            for (var i = 0; i < original_data['path'].length; ++i) {
                if ((original_data['normscore'][i] >= min_score) && (original_data['normscore'][i] <= max_score) && (original_data['featfreq'][i] >= min_featfreq) &&
                    (original_data['featcnt'][i] >= min_featcnt)) {
                    // filter by java
                    if (kind == "Java" && original_data['path'][i].indexOf(java_suffix, original_data['path'][i].length - java_suffix.length) === -1)
                        continue;
                    // filter by native
                    if (kind == "Native" && original_data['path'][i].indexOf(native_suffix, original_data['path'][i].length - native_suffix.length) === -1)
                        continue;
                    // filter by search regex
                    if (!re.test(original_data['name'][i])) {
                        console.log("mismatch: " + original_data['name'][i]);
                        continue;
                    }
                    // this row is the expected kind
                    data[key].push(original_data[key][i]);
                }
            }
        }
        source.trigger('change');
        target.trigger('change');
        """
        generic_callback = CustomJS(
            args=dict(source=self.source, original_source=self.original_source,
                      search_input=search_input,
                      max_matching_score_slider=max_matching_score_slider,
                      min_matching_score_slider=min_matching_score_slider, featfreq_slider=featfreq_slider,
                      featcnt_slider=featcnt_slider, kind_select=kind_select, target=self.data_table),
            code=combined_callback_code
        )
        min_matching_score_slider.callback = generic_callback
        max_matching_score_slider.callback = generic_callback
        featfreq_slider.callback = generic_callback
        featcnt_slider.callback = generic_callback
        search_button.callback = generic_callback
        kind_select.callback = generic_callback

        # install callback when a row gets selected
        self.source.on_change('selected', self.selected_callback)

        ###########################################################
        # Main
        ###########################################################
        controls = [min_matching_score_slider, max_matching_score_slider, featfreq_slider, \
                    featcnt_slider, kind_select, file_select, search_input, search_button, \
                    download_button, compare_button]
        plots_box = widgetbox(*controls, width=800, sizing_mode="fixed")
        layout = column(plots_box, self.data_table, sizing_mode="fixed")

        return layout

    def disable_all(self):
        self.data_table.disable = True

    def start_process(self, cmd_list, cwd=os.getcwd()):
        try:
            import subprocess
            p = subprocess.Popen(cmd_list, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            o = p.communicate()
            self.logger.info("%s", o)
            rc = p.returncode
            if rc < 0:
                self.logger.error("%s terminated with %d", cmd_list, rc)
                return False
            return True
        except Exception as e:
            self.logger.error("%s raise exception: %s", cmd_list, str(e))
            return False

    def sort_csv(self, path):
        try:
            import csv
            reader = csv.DictReader(open(path, 'r'))
            res = sorted(reader, key=lambda k: k['feature'].lower())
            writer = csv.DictWriter(open(path, 'w'), reader.fieldnames)
            writer.writeheader()
            writer.writerows(res)
            return True;
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.logger.error("[%s, %s, %s] failed to sort file %s: %s", \
                              exc_type, fname, exc_tb.tb_lineno, path, str(e))
            return False

    def vim_diff(self, fromfile, tofile):
        try:
            path = '/tmp/' + os.path.basename(fromfile) + '_' + os.path.basename(tofile) + '_diff.html'
            self.start_process(['/usr/bin/gvim', '-d', fromfile, tofile, '-c', 'colorscheme zellner', \
                           '-c', 'TOhtml', '-c', 'w!', path, '-c', 'q!', '-c', 'q!', '-c', 'q!'])
            f = open(path,'w')
            f.write(diff)
            f.close()
            return path
        except Exception as e:
            self.logger.error("failed to diff files %s, %s: %s", fromfile, tofile, str(e))
            return None

    def html_diff(self, fromfile, tofile):
        try:
            import difflib
            fromlines = open(fromfile, 'U').readlines()
            tolines = open(tofile, 'U').readlines()
            diff = difflib.HtmlDiff().make_file(fromlines,tolines,fromfile,tofile)
            path = '/tmp/' + os.path.basename(fromfile) + '_' + os.path.basename(tofile) + '_diff.html'
            f = open(path,'w')
            f.write(diff)
            f.close()
            return path
            #import webbrowser
            #webbrowser.open_new_tab(path)
        except Exception as e:
            self.logger.error("failed to diff files %s, %s: %s", fromfile, tofile, str(e))
            return None

    def compare_callback(self):
        try:
            cwd = os.path.abspath('../detector')
            self.logger.info('cwd: %s', cwd)
            for software_name, path in self.selected_data:
                url = self.REPO_URL_PROTOCOL +  "://" + self.REPO_URL_HOSTNAME + '/' + software_name
                self.logger.info("comparing %s and %s", url, path)
                if self.start_process(['python', 'detector.py', 'index', '-d', url], cwd):
                    idxfile_path = '/tmp/index_dump_' + software_name.replace('/', '_') + '.csv'
                    if os.path.isfile(idxfile_path) and os.stat(idxfile_path).st_size > 0 and \
                        self.start_process(['python', 'detector.py', 'search', '-d', path], cwd):
                        srchfile_path = '/tmp/search_dump_' + os.path.basename(path) + '.csv'
                        if os.path.isfile(srchfile_path) and os.stat(srchfile_path).st_size > 0:
                            self.sort_csv(idxfile_path)
                            self.sort_csv(srchfile_path)
                            diff_file_path = self.html_diff(idxfile_path, srchfile_path)
                            #diff_file_path = self.vim_diff(idxfile_path, srchfile_path)

                            diff_callback_code = """
                            var filename = 'violations.csv';
                            var blob = new Blob([filetext], { type: 'html;charset=utf-8;' });
                            
                            //addresses IE
                            if (navigator.msSaveBlob) {
                                //navigator.msSaveBlob(blob, filename);
                            }
                            else {
                                var link = document.createElement("a");
                                link = document.createElement('a');
                                link.href = URL.createObjectURL(blob);
                                link.download = filename;
                                link.target = "_blank";
                                link.style.visibility = 'hidden';
                                link.dispatchEvent(new MouseEvent('click'));
                            }
                            """

            return True
        except Exception as e:
            self.logger.error("failed to compare: %s", str(e))
            return False

    def selected_callback(self, attr, old, new):
        selected_indices = new['1d']['indices']
        if selected_indices:
            for idx in selected_indices:
                self.selected_data.append((self.source.data['software_name'][idx], self.source.data['path'][idx]))

def update(viewer):
    #viewer.logger.info("changing the source path at location 0")
    #viewer.source.patch({'path': [(0, 'hello world')]})
    #viewer.source.trigger('change')
    viewer.update()


###########################################################
# Main
###########################################################
def main():
    viewer = Viewer()
    data = viewer.get_data()
    layout = viewer.create_ui(data)
    curdoc().add_root(layout)
    #partial_update = partial(update, viewer=viewer)
    #curdoc().add_periodic_callback(partial_update, 500)

main()
