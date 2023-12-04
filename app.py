# import os
# import sys

# print(os.path.dirname(__file__))
# path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../mockoauthserver"))
# print(path)
# sys.path.append(path)
import logging                
from fastapi import FastAPI, Request, status
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from mockoauthserver.server import createServer
app = FastAPI()

authserver = createServer()
authserver.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=['*'],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
app.mount("/oauth", authserver)

@app.get("/hello")
def hello(request: Request):
    headers = request.headers
    auth = request.auth
    user = request.scope["user"]
    return {'hello': 'world', 'headers': {**headers}, 'auth': f"{auth}", 'user': user}

# from starlette_oauth2_api import AuthenticateMiddleware
# app.add_middleware(AuthenticateMiddleware,
#     providers={
#         'local': {
#             'keys': 'http://localhost:9888/oauth/publickey',
#             'issuer': 'http://localhost:9888/oauth',
#             'audience': '852159111111-xxxxxx.apps.googleusercontent.com',
#         }
#     },
#     public_paths={'/'},
# )

from starlette.authentication import (
    AuthCredentials, AuthenticationBackend, AuthenticationError
)
from starlette.middleware.authentication import AuthenticationMiddleware

class BasicAuthMiddleware(AuthenticationMiddleware):
    @staticmethod
    def on_error(conn, exc):
        return RedirectResponse(f"/oauth/login2", status_code=status.HTTP_303_SEE_OTHER)
        pass

class BasicAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn):
        client = conn.client
        headers = conn.headers
        cookies = conn.cookies
        logging.info(f'{client}, {headers}, {cookies}')
        user = {"id": "2d9dc5ca-a4a2-11ed-b9df-0242ac120003", "name": "John", "surname": "Newbie"}
        return AuthCredentials(["authenticated"]), user

app.add_middleware(BasicAuthMiddleware, backend=BasicAuthBackend())