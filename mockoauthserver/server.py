from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

pem_private_key = encrypted_pem_private_key = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public_key = key.public_key().public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print('generated public key')
print(pem_public_key.decode('ascii'))

import jwt # https://jwt.io/introduction

def asJWT(data={}):
    result = jwt.encode(data, pem_private_key, algorithm="RS256")
    return result

import random
import string
import datetime

def randomString(size=32):
    return ''.join((random.choice(string.ascii_letters + string.digits) for _ in range(size)))


def loginPage(key=None, token=None, suggestedUsers=[]):
    if key is None:
        key = randomString()

    if len(suggestedUsers) == 0:
        userHelp = ''
    else:    
        userHelp = 'Try to use one of emails: ' + ', '.join(suggestedUsers)
    if token is None:
        tokenHtml = ''
    else:
        tokenHtml = f'''<div class="alert alert-warning" role="alert">{token}</div>'''

    _loginPage = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <title>Login Page</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js"></script>
    </head>
    <body>

    <div class="container-fluid p-5 bg-primary text-white text-center">
    <h1>Login Page</h1>
    <p>Enter your email and password</p> 
    </div>
    
    <div class="container mt-5">
    <div class="row">
        <div class="col">
        <form method="post">
            <div class="mb-3">
            <label for="username" class="form-label">Email address</label>
            <input type="email" class="form-control" id="username" name="username" aria-describedby="emailHelp">
            <div id="emailHelp" class="form-text">{userHelp}</div>
            </div>
            <div class="mb-3">
            <label for="password" class="form-label">Password (can be any)</label>
            <input type="password" class="form-control" id="password" name="password">
            <input type="hidden" class="form-control" id="key" name="key" value={key}>
            </div>
            {tokenHtml}
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        </div>
    </div>
    </div>

    </body>
    </html>
    """
    return _loginPage

def createToken(client_state='', expires_in=3600, refresh_token_expires_in=24*3600, iss=None):
    code = "C-" + randomString()
    accesstoken = "ACCT-" + randomString()
    refreshtoken = "REFT-" + randomString()
    id_token = "IDT-" + randomString()
    date_of_creation = datetime.datetime.now(tz=datetime.timezone.utc)
    result = {
        'id_token': id_token,

        'access_token': accesstoken,
        'date_of_creation': date_of_creation,
        'expires_in': expires_in,

        'refresh_token': refreshtoken,
        'refresh_token_expires_in': date_of_creation + datetime.timedelta(refresh_token_expires_in),

        'code': code,
        'state': client_state,
        'token_type': "Bearer",

        'exp': date_of_creation + datetime.timedelta(seconds=expires_in)
    }
    if iss:
        result["iss"] = iss

    return result

def extractKeys(data={}, keys=[]):
    result = {}
    for key in keys:
        value = data.get(key, None)
        if value is not None:
            result[key] = value
    return result

from fastapi import FastAPI, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi import Form, Header
from typing import Union, Optional

def createServer(iss="http://localhost:8000/publickey", db_users={"id": "5563aa07-45c8-4098-af17-f2e8ec21b9df", "email": "someone@somewhere.world"}):
    db_table_codes = {}
    db_table_params = {}
    
    db_table_tokens = {}
    db_table_refresh_tokens = {}

    app = FastAPI()

    def tokenFromCode(code):
        storedParams = db_table_codes.get(code, None)
        if storedParams is None:
            return None

        del db_table_codes[code] # delete code, so it is not possible to use it more?

        token = createToken(iss=iss)

        tokenRow = {**token, **storedParams}
        db_table_tokens[tokenRow['access_token']] = tokenRow
        db_table_refresh_tokens[tokenRow['refresh_token']] = tokenRow

        responseJSON = extractKeys(tokenRow, ['token_type', 'access_token', 'expires_in', 'refresh_token'])
        return responseJSON

    @app.get('/login')
    async def getLoginPage(response_type: Union[str, None] = 'code', 
        client_id: Union[str, None] = 'SomeClientID', state: Union[str, None] = 'SomeState', redirect_uri: Union[str, None] = 'redirectURL'):

        # if there is a sign that user is already logged in, then appropriate redirect should be returned (see method postNameAndPassword)

        storedParams = {
            "response_type": response_type, 
            "client_id": client_id, 
            "state": state, 
            "redirect_uri": redirect_uri
        }

        # here client_id should be checked
        # here redirect_uri should be checked (client should use always same redirect uri)

        # save info into db table
        key = randomString()
        db_table_params[key] = storedParams

        # return login page
        suggestedUsers = [user["email"] for user in db_users.values()]
        return HTMLResponse(loginPage(key, suggestedUsers=suggestedUsers))

    @app.get('/login2')
    async def getLoginPage(response_type: Union[str, None] = 'code', 
        client_id: Union[str, None] = 'SomeClientID', state: Union[str, None] = 'SomeState', redirect_uri: Union[str, None] = 'redirectURL'):

        # if there is a sign that user is already logged in, then appropriate redirect should be returned (see method postNameAndPassword)

        storedParams = {
            "response_type": response_type, 
            "client_id": client_id, 
            "state": state, 
            "redirect_uri": redirect_uri
        }

        # here client_id should be checked
        # here redirect_uri should be checked (client should use always same redirect uri)

        # save info into db table
        key = randomString()
        db_table_params[key] = storedParams

        # return login page
        suggestedUsers = [user["email"] for user in db_users.values()]
        return HTMLResponse(loginPage(key, suggestedUsers=suggestedUsers))

    @app.post('/login2', )
    async def postNameAndPassword(response: Response, username: str = Form(None), password: str = Form(None), key: str = Form(None)):
        
        # username and password must be checked here, if they match eachother

        # retrieve previously stored data from db table
        storedParams = db_table_params.get(key, None)
        if ((storedParams is None) or (key is None)):
            # login has not been initiated appropriatelly
            #HTMLResponse(content=f"Bad OAuth Flow, {key} has not been found", status_code=404)
            return RedirectResponse(f"./login2", status_code=status.HTTP_303_SEE_OTHER)

        del db_table_params[key] # remove key from table

        token = createToken()
        user_ids = map(lambda user: user["id"], filter(lambda user: user["email"] == username))
        user_id = next(user_ids, None)

        storedParams['user'] = {"name": username, "email": username, "id": user_id}
        storedParams['user_id'] = user_id
        tokenRow = {**token, **storedParams}

        db_table_tokens[tokenRow['access_token']] = tokenRow
        db_table_refresh_tokens[tokenRow['refresh_token']] = tokenRow

        responseJSON = extractKeys(tokenRow, ['token_type', 'access_token', 'expires_in', 'refresh_token', 'user_id'])
        token = asJWT(responseJSON)

        response = HTMLResponse(loginPage(token=f'{token}<br />{responseJSON}'))
        response.set_cookie(key="authorization", value=token)

        return response

    #pip install python-multipart
    @app.post('/login')
    async def postNameAndPassword(username: str = Form(None), password: str = Form(None), key: str = Form(None)):
        
        # username and password must be checked here, if they match eachother

        # retrieve previously stored data from db table
        storedParams = db_table_params.get(key, None)
        if ((storedParams is None) or (key is None)):
            # login has not been initiated appropriatelly
            HTMLResponse(content=f"Bad OAuth Flow, {key} has not been found", status_code=404)
            

        # remove stored data from table
        del db_table_params[key] # remove key from table

        # store code and related info into db table
        code = randomString()
        user_ids = map(lambda user: user["id"], filter(lambda user: user["email"] == username))
        user_id = next(user_ids, None)

        storedParams['user'] = {"name": username, "email": username, "id": user_id}
        storedParams['user_id'] = user_id

        db_table_codes[code] = storedParams
        if '?' in storedParams['redirect_uri']:
            result = RedirectResponse(f"{storedParams['redirect_uri']}&code={code}&state={storedParams['state']}", status_code=status.HTTP_302_FOUND)
        else:
            result = RedirectResponse(f"{storedParams['redirect_uri']}?code={code}&state={storedParams['state']}", status_code=status.HTTP_302_FOUND)
        return result

    @app.post('/token')
    async def exchangeCodeForToken(
        response: Response, 
        grant_type: str = Form(None), code: str = Form(None), client_id: str = Form(None), 
        client_secret: Optional[str] = Form(None),
        code_verifier: Optional[str] = Form(None),
        refresh_token: Optional[str] = Form(None)):

        # add header Cache-Control: no-store
        response.headers["Cache-Control"] = "no-store"

        # if web app flow is used, client_secret should be checked
        # if PKCE flow is used, code_verifier must be returned

        if grant_type == 'authorization_code':
            # retrieve previously stored data from db table

            responseJSON = tokenFromCode(code)

            if responseJSON is None:
                # login has not been initiated appropriatelly
                return JSONResponse(content={
                    'error': 'invalid_request',
                    'error_description': f'Bad OAuth Flow, code {code} has not been found'
                    }, status_code=404)

            pass

        if grant_type == 'refresh_token':
            storedParams = db_table_refresh_tokens.get(refresh_token, None)
            if tokenRow is None:
                # refresh token does not exists
                return JSONResponse(content={
                    'error': 'invalid_request',
                    'error_description': f'Bad OAuth Flow, refresh_token {refresh_token} has not been found'
                    }, status_code=404)

            # remove token from tables
            del db_table_tokens[tokenRow['access_token']]
            del db_table_refresh_tokens[tokenRow['refresh_token']]
            
            if storedParams['refresh_token_expires_in'] > datetime.datetime.now(tz=datetime.timezone.utc):
                # refresh token has expired
                return JSONResponse(content={
                    'error': 'invalid_refresh_token',
                    'error_description': f'Bad OAuth Flow, refresh_token {refresh_token} has not been found'
                    }, status_code=404)

            token = createToken()

            tokenRow = {**storedParams, **token}
            db_table_tokens[tokenRow['access_token']] = tokenRow
            db_table_refresh_tokens[tokenRow['refresh_token']] = tokenRow

            responseJSON = extractKeys(tokenRow, ['token_type', 'access_token', 'expires_in', 'refresh_token', 'user_id'])
            pass

        if code_verifier is not None:
            # PKCE flow
            responseJSON[code_verifier] = code_verifier

        return asJWT(responseJSON)

    @app.get('/userinfo')
    async def getUserInfo(authorization: Union[str, None] = Header(default='Bearer _')):
        print("getUserInfo", authorization)
        [_, token] = authorization.split(' ')

        if token == '_':
            return JSONResponse(content={
                'error': 'invalid_request',
                'error_description': f'Bad OAuth Flow, token {token} has not been found'
                }, status_code=404)

        print(db_table_tokens)
        tokenRow = db_table_tokens.get(token, None)
        if tokenRow is None:
            # login has not been initiated appropriatelly
            return JSONResponse(content={
                'error': 'invalid_request',
                'error_description': f'Bad OAuth Flow, token {token} has not been found'
                }, status_code=404)

        responseJSON = extractKeys(tokenRow, ['user'])

        # return asJWT(responseJSON)
        return JSONResponse(content=responseJSON)

    @app.get('/logout')
    async def logout(authorization: Union[str, None] = Header(default='Bearer _')):
        [_, token] = authorization.split[' ']
        tokenRow = db_table_refresh_tokens.get(token, None)
        if not(tokenRow is None):
            # remove token from tables
            del db_table_tokens[tokenRow['access_token']]
            del db_table_refresh_tokens[tokenRow['refresh_token']]

        # where to go?
        return RedirectResponse(f"./login?redirect_uri={tokenRow['redirect_uri']}")

    @app.get('/publickey')
    async def getPublicKeyPem():
        return pem_public_key.decode('ascii')


    return app