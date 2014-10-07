import logging
import os
import csv
import tempfile

import ckan.plugins as p


log = logging.getLogger(__name__)


class IntroExamplePluginChanges(p.SingletonPlugin):

    p.implements(p.IConfigurer)
    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IAuthFunctions)
    p.implements(p.IActions)

    ## IConfigurer
    def update_config(self, config):
        '''
        This method allows to access and modify the CKAN configuration object
        '''

        log.info('You are using the following plugins: {0}'
                 .format(config.get('ckan.plugins')))

        # Check CKAN version
        # To raise an exception instead, use:
        #   p.toolkit.require_ckan_version('2.1')
        if not p.toolkit.check_ckan_version('2.1'):
            log.warn('This extension has only been tested on CKAN 2.1!')

        

    ## IRoutes
    def after_map(self, map):

        controller = 'ckanext.intro.plugin_changes:CustomController'
        

        map.connect('/changes', controller=controller, action='changes_report')

        return map

    ## IAuthFunctions
    def get_auth_functions(self):

        # Return a dict with the auth functions that we want to override
        # or add
        return {
            'datasets_changes_report_csv': datasets_changes_report_csv_auth,
            
        }

    ## IActions
    def get_actions(self):
        # Return a dict with the action functions that we want to add
        return {
            'datasets_changes_report_csv': datasets_changes_report_csv,
        }




# Ideally auth functions should have the same name as their actions and be
# kept on different modules. To keep things simple and all the functions on
# the same file we will name this one slightly different.
def datasets_changes_report_csv_auth(context, data_dict):

    return {'success': False, 'msg': 'Only sysadmins can get a report'}


def datasets_changes_report_csv(context, data_dict):
    '''
    A custom action function that generates a CSV file with metadata from
    all datasets in the CKAN instance and stores it on a temporal file,
    returning its path.

    Note how we call `p.toolkit.check_access` to make sure that the user is
    authorized to perform this action.
    '''

    p.toolkit.check_access('datasets_changes_report_csv', context, data_dict)

    # Get all datasets from the search index (actually the first 100)
    data_dict = {
        'q': '*:*',
        'rows': 100,
    }
    result = p.toolkit.get_action('recently_changed_packages_activity_list')(context, data_dict)
    print 'RESULT :::::::   '
    print result
    # Create a temp file to store the csv
    fd, tmp_file_path = tempfile.mkstemp(suffix='.csv')

    with open(tmp_file_path, 'w') as f:
        field_names = ['timestamp', 'package', 'activity_type', 'name', 'title']
        field_names_dic = ['timestamp', 'activity_type', 'name', 'title']
        writer = csv.DictWriter(f, fieldnames=field_names_dic,
                                quoting=csv.QUOTE_ALL)
        writer.writerow(dict((n, n) for n in field_names_dic))
        for dataset in result:
            row = {}
            for field_name in field_names:
                if dataset['data']['package']['type']=='dataset':
                    if field_name == 'package':
                        row['name'] = dataset['data']['package']['name'].encode('utf8')
                        row['title'] = dataset['data']['package']['title'].encode('utf8')
                    if field_name == 'timestamp' or field_name == 'activity_type':
                        row[field_name] = dataset[field_name].encode('utf8')
            writer.writerow(row)
        return {
            'file': tmp_file_path,
        }


class CustomController(p.toolkit.BaseController):

    def changes_report(self):
        try:
            result = p.toolkit.get_action('datasets_changes_report_csv')()
        except p.toolkit.NotAuthorized:
            p.toolkit.abort(401, 'Not authorized to see this report')
        with open(result['file'], 'r') as f:
            content = f.read()

        # Clean up
        os.remove(result['file'])

        # Modify the headers of the response to reflect that we are outputing
        # a CSV file
        p.toolkit.response.headers['Content-Type'] = 'application/csv'
        p.toolkit.response.headers['Content-Length'] = len(content)
        p.toolkit.response.headers['Content-Disposition'] = \
            'attachment; filename="recently_changed.csv"'
        return content