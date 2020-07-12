from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import render

from . import utils


def main(request):
    token = request.COOKIES.get('csrftoken')
    if not token:
        token = get_token(request)
        request.META['CSRF_COOKIE'] = token
    code_verifier = utils.gen_code_verifier()
    url = utils.get_authorization_uri(code_verifier, scope=None, state=token)
    response = render(request, 'main/index.html', {'login_url': url})
    response.set_cookie('code_verifier', code_verifier)
    return response


def callback(request):
    error = request.GET.get('error')
    state = request.GET.get('state')
    response = {'state': state, 'success': False}
    if error:
        response['error'] = error
    elif state != request.COOKIES.get('csrftoken'):
        response['error'] = 'invalid_state'
    else:
        spotify_response = utils.get_access_token(
            request.GET.get('code'),
            request.COOKIES.get('code_verifier')
        )
        error = spotify_response.get('error')
        if error:
            response['error'] = error
            response['error_description'] = spotify_response.get('error_description')
        else:
            response = spotify_response
    return JsonResponse(response)
