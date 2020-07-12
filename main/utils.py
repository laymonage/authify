import base64
import hashlib
import os
import secrets
import urllib.parse

import requests


def gen_code_verifier(nbytes=64):
    return secrets.token_urlsafe(nbytes)


def _gen_code_challenge(code_verifier):
    sha = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(sha).decode()[:-1]


def _gen_auth_uri(code_challenge, scope=None, state=None):
    scope = scope or os.getenv('SPOTIFY_API_SCOPE')
    base = os.getenv('SPOTIFY_AUTHORIZE_URI')
    url = urllib.parse.urlparse(base)
    query_params = {
        'client_id': os.getenv('SPOTIFY_CLIENT_ID'),
        'response_type': 'code',
        'redirect_uri': os.getenv('SPOTIFY_REDIRECT_URI'),
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge,
    }
    if scope:
        query_params['scope'] = scope
    if state:
        query_params['state'] = state
    query = urllib.parse.urlencode(query_params)
    return urllib.parse.urlunparse(url._replace(query=query))


def get_authorization_uri(code_verifier, scope=None, state=None):
    return _gen_auth_uri(
        _gen_code_challenge(code_verifier),
        scope=scope,
        state=state
    )


def get_access_token(code, code_verifier):
    url = os.getenv('SPOTIFY_TOKEN_URI')
    data = {
        'client_id': os.getenv('SPOTIFY_CLIENT_ID'),
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': os.getenv('SPOTIFY_REDIRECT_URI'),
        'code_verifier': code_verifier,
    }
    return requests.post(url, data=data).json()


def refresh_access_token(refresh_token):
    url = os.getenv('SPOTIFY_TOKEN_URI')
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': os.getenv('SPOTIFY_CLIENT_ID'),
    }
    return requests.post(url, data=data).json()
