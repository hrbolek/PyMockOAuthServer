import aiohttp

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from typing import Optional

import jwt # https://jwt.io/introduction
import random
import datetime
import string

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

def asJWT(data={}):
    result = jwt.encode(data, pem_private_key, algorithm="RS256")
    return result

def randomString(size=32):
    return ''.join((random.choice(string.ascii_letters + string.digits) for _ in range(size)))

def createToken(client_state='', expires_in=3000, refresh_token_expires_in=24*3600):
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
    return result

def extractKeys(data={}, keys=[]):
    result = {}
    for key in keys:
        value = data.get(key, None)
        if value is not None:
            result[key] = value
    return result

def createMockApiClient(
    callbackUrlPrefix,
    oauthServerLoginUrl, 
    oauthServerLogoutUrl,
    oauthServerTokenUrl,
    oauthServerPublicKeyUrl,
    oauthServerUserinfoUrl,
    mainAppPageUrl,
    cookieName,
    clientid = "clientid",
    clientsecret = "clientsecret"
    ):
    app = FastAPI()


    db_table_acctokens = {}
    db_table_refreshtokens = {}

    @app.get("/login")
    async def login(code: Optional[str] = None, state: Optional[str] = None):
        if code is None:
            #just asking for login html page
            return RedirectResponse(url=oauthServerLoginUrl + "?redirect=")
        
        queryparams = {
            "client_id": clientid,
            "client_secret": clientsecret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callbackUrlPrefix + "/login"
        }
       
        async with aiohttp.ClientSession() as session:
            async with session.post(oauthServerTokenUrl, params=queryparams) as resp:
                jwttext = await resp.text()

        print("jwttext", jwttext)

        async with aiohttp.ClientSession() as session:
            async with session.post(oauthServerPublicKeyUrl) as resp:
                serverpublickey = await resp.text()

        async with aiohttp.ClientSession() as session:
            async with session.post(oauthServerUserinfoUrl) as resp:
                userinfo = await resp.text()

        servertoken = jwt.decode(jwttext, serverpublickey)
        print("token", servertoken)
        print("access_token", servertoken.access_token)

        localtoken = createToken()
        localtoken['user'] = userinfo
        localtoken['servertoken'] = servertoken
        localtoken['serverpublickey'] = serverpublickey
        
        # db_table_acctokens = {}
        db_table_acctokens[localtoken['access_token']] = localtoken
        db_table_refreshtokens[localtoken['refersh_token']] = localtoken

        clienttoken = extractKeys(localtoken, ['access_token', 'refersh_token', 'user', 'expires_in'])
        cookievalue = asJWT(clienttoken)
        response = RedirectResponse(url=mainAppPageUrl)
        response.set_cookie(key="cookieName", value=cookievalue)
        return response