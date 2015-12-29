"""
File: bb_auth.py
Author: Brent Mackey
Github: https://github.com/bjdm/bb_auth
Description: Script to authenticate a requests session object to access
the QUT Blackboard webapp.
"""

import logging

import requests
from bs4 import BeautifulSoup as bs

bb_url = 'https://blackboard.qut.edu.au'
login_url = 'https://esoe.qut.edu.au/qut-login/login'


def submit_hidden_form(session, soup, data_type):
    """ Handles submiting the authentication tokens at 3 stages during
    the handshake. SAML is sent to IdP server, then JSON web token is
    submitted after submitting credentials, then SAML again to finish.
    Note: data_type (str) should only be 'saml' or 'jwt'
    """
    if data_type == 'saml':
        data = {'SAMLResponse': soup.find('input')['value']}
    elif data_type == 'jwt':
        data = {'jwtPayload': soup.find('input')['value']}

    response_url = soup.find('form')['action']

    return session.post(response_url, data)


def awaiting_saml(soup):
    """ Confirms hidden field with SAML token """
    return soup.find('input')['name'] == 'SAMLResponse' or \
        soup.find('input')['name'] == 'SAMLRequest'


def awaiting_jwt(soup):
    """ Confirms hidden field with the JSON web token """
    return soup.find('input')['name'] == 'jwtPayload'


def awaiting_login(soup):
    """ Confirms valid login form exists """
    return soup.find('form')['name'] == 'loginSuccessful'


def authenticated(session, soup=None):
    """ Confirms successful authentication by either following session
    context until Blackboard landing page or launches new request
    for Blackboard home page and checks for landing page.
    """
    if soup is not None:
        if soup.title.text[0:7] == 'Welcome':
            logging.info('Successfully Authenticated.')
            return True
    else:
        if bs(session.get(bb_url).content, 'lxml').title[0:7] \
                == 'Welcome':
            logging.info('Successfully Authenticated.')
            return True


def submit_login_form(session, username, password):
    """ Submits login form with the user's credentials """
    return session.post(login_url, data={'username': username,
                        'password': password})


def handle_sso_redirect(username, password, session, soup):
    """ Handles shibboleth redirections and submits relevant tokens
    to the correct authentication servers.
    Returns response objects to keep the cookiejar fresh
    """
    # Determine which stage of the handshake the session is in
    if authenticated(session, soup):
        logging.info('Successfully Authenticated.')
        return session.get(bb_url)
    elif awaiting_saml(soup):
        logging.info('Submitting SAMLResponse to %s' % (soup.find('form')
                                                        ['action']))
        return submit_hidden_form(session, soup, data_type='saml')
    elif awaiting_jwt(soup):
        logging.info('Submitting jwtPayload to %s' % (soup.find('form')
                                                      ['action']))
        return submit_hidden_form(session, soup, data_type='jwt')
    elif awaiting_login(soup):
        logging.info('Attempting to log into %s as %s' % (soup.title.text,
                                                          username))
        return submit_login_form(session, username, password)
    else:
        logging.info('Unexpected webpage. Redirecting to main login portal')
        return session.get(login_url)


def authenticate(username, password, session=None):
    """ Authenticates a requests session for accessing QUT Blackboard and returns
    it. If no session context is passed to the function, a new instance is made
    then returned.
    Args:
        username (str): The student username for accessing Blackboard
        password (str): The respective students password for Blackboard
        session (Optional[requests.Session object]): Session context for
        connection pool
    Returns:
        requests.Session object with authenticated connection pool and cookie
        jar
    """
    # Create a new session if one doesn't exist
    if session is None:
        logging.info('Initiatiating new session.')
        session = requests.Session()
    # Parse the response of the inital Blackboard connection
    soup = bs(session.get(bb_url).content, 'lxml')

    # Begin shibboleth authentication
    logging.info('Begginging authentication as %s' % username)
    while not authenticated(session, soup):
        soup = bs(handle_sso_redirect(username, password, session,
                                      soup).content, 'lxml')
    return session


def main():
    logging.basicConfig(level=logging.INFO)
    session = requests.Session()
    un = input('Please enter your username: ')
    try:
        import os
        os.system('stty -echo')
        pw = input('Please enter your password:')
        os.system('stty echo')
    except ImportError:
        print('Your system is incapable of hiding input. Proceed with caution')
        pw = input('Please enter your password:')
    finally:
        authenticate(un, pw, session)

    return


if __name__ == "__main__":
    main()
