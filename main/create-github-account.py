#!/usr/bin/env python

from os.path import join, dirname
import random
import traceback
import mechanize
import click

'''
- https://github.com
    - forms: user[login], user[email], user[password]
    - hidden: <input name="utf8" type="hidden" value="&#x2713;" /><input name="authenticity_token" type="hidden" value="l6T16sFV3vaNnyjcCrdkCmu+yiAl51CUCZSAvculrxmXqZHd9Fu5b0eAx28k0YJqVyR2L7oeurT69b99tx6PpA==" />
    - button: "Sign up for GitHub"
    - post URL: https://github.com/join?source=button-home
    - Context: <a href="/join?source=button-home" class="btn btn-block btn-theme-green btn-jumbotron" rel="nofollow">Sign up for GitHub</a>
    - Target: https://github.com/join/plan


- forms:
    utf8:&#x2713;
    authenticity_token:O70u4yOVUkMl9AW0+qOItHZNjhJsMWO9NSrLx44QNV39SgUfaFVPKGI8WwUWHGRqxxhPgaTBK3/UkPlUiuRO+w==
    plan:free
    post URL: https://github.com/join/plan
'''

ACCOUNTS_FP = join(dirname(__file__), 'accounts.txt')


@click.command()
@click.option('--username', 'username', default=None)
@click.option('-n', 'num', default=1)
def create_github_account_cli(username, num):
    if num == 1 and username is not None:
        create_account_from_username(username)
    else:
        for i in xrange(num):
            print 'Creating %d/%d' % (i + 1, num)
            username = generate_random_username()
            create_account_from_username(username)


def generate_random_username():
    return 'somethingfishy' + str(random.randrange(1000, 10000000))


def create_account_from_username(username):
    '''Returns the details of the new account.'''
    username, email, password = generate_account_details(username)
    success = create_new_account(username, email, password)
    if success:
        print 'Created account for "%s".' % username
        with open(ACCOUNTS_FP, 'a') as f:
            f.write('\"%s@gmail.com\": \"%spass\",\n' % (username, username))
        return username, email, password
    else:
        print 'FAILED to create account for "%s".' % username
        return None


def generate_account_details(username):
    username = username
    email = '%s@gmail.com' % username
    password = username + 'pass'
    return username, email, password


def create_new_account(username, email, password):
    '''It returns True/False.'''

    browser = mechanize.Browser()
    browser.set_handle_robots(False)
    browser.addheaders = [
        ('User-agent',
         'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11'),
        ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
        ('Accept-Encoding', 'gzip,deflate,sdch'),
        ('Accept-Language', 'en-US,en;q=0.8'),
        ('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.3')
    ]
    browser.set_handle_gzip(True)
    res = browser.open('https://github.com')
    browser.select_form(nr=1)
    browser['user[login]'] = username
    browser['user[email]'] = email
    browser['user[password]'] = password
    s = browser.submit()

    second_page = s.read()
    landing_page_fp = '/tmp/landing-%s.html' % username
    with open(landing_page_fp, 'w') as f:
        f.write(second_page)

    expected_string = 'taken your first step into a larger world, <strong>@%s' % username
    second_page = second_page.decode('ascii', 'ignore')
    if second_page.find(expected_string) >= 0:
        print 'SUCCESS for user %s' % username
        return True
    else:
        # something went wrong
        error_fp = '/tmp/errorpage-%s.html' % username
        with open(error_fp, 'w') as f:
            f.write(second_page)
        print 'Something went wrong. Error page dumped to "%s"' % error_fp
        return False


if __name__ == '__main__':
    create_github_account_cli()
