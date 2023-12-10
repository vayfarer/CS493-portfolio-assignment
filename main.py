# Michael Chen
# OSU CS 493 Portfolio Assignment
# 12/10/2023

"""Python Flask WebApp Auth0 integration example
Based on https://auth0.com/docs/quickstart/webapp/python#setup-your-routes
"""

import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for

from flask import request, make_response, jsonify
from google.cloud import datastore
import constants
client = datastore.Client()

from urllib.request import urlopen
from jose import jwt

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

CLIENT_ID = env.get("AUTH0_CLIENT_ID")
CLIENT_SECRET = env.get("AUTH0_CLIENT_SECRET")
DOMAIN = env.get("AUTH0_DOMAIN")
# For example
# DOMAIN = 'fall21.us.auth0.com'
ALGORITHMS = ["RS256"]

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    response.mimetype = 'application/json'
    return response


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)



# Controllers API
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    # add users if unique
    query = client.query(kind=constants.users)
    query.add_filter("user_sub", "=", token['userinfo']['sub'])
    results = list(query.fetch())
    if not results:
        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({'user_sub': token['userinfo']['sub']})
        client.put(new_user)
    return redirect("/")


@app.route("/login")
def login():
    print(url_for("callback", _external=True))
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


@app.route("/checkjwt", methods=['HEAD'])
def check_jwt():
    try:
        payload = verify_jwt(request)
        return "", 200
    except AuthError as error:
        return handle_auth_error(error)


################################################################################
# API
################################################################################
def res_error(msg:str, code:int):
    error = {'Error': msg}
    res = make_response(json.dumps(error), code)
    res.mimetype = 'application/json'
    return res


@app.route('/users', methods=['GET'])
def users_get():
    if not request.accept_mimetypes.accept_json:
        return res_error("application/json response only", 406)

    if request.method == 'GET':
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        for e in results:
            e['id'] = e.key.id
        res = make_response(json.dumps(results), 200)
        res.mimetype = 'application/json'
        return res


def get_user(user_sub):
    query = client.query(kind=constants.users)
    query.add_filter("user_sub", "=", user_sub)
    user_list = list(query.fetch())
    if user_list:
        return True
    else:
        return False


@app.route('/boats', methods=['POST', 'GET'])
def boats_post_get():

    try:
        payload = verify_jwt(request)
    except AuthError as error:
        return handle_auth_error(error)

    if not request.accept_mimetypes.accept_json:
        return res_error("application/json response only", 406)

    if request.method == 'POST':
        if not get_user(payload['sub']):
            return res_error("User not registered", 403)

        content = request.get_json()
        if "name" not in content or "type" not in content or "length" not in content:
            return res_error('The request object is missing at least one of the required attributes', 400)

        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"],
                         "length": content["length"], "slip": None,
                         "owner": payload['sub']})
        client.put(new_boat)
        new_boat['id'] = new_boat.key.id
        new_boat['self'] = request.base_url + "/" + str(new_boat.key.id)

        res = make_response(json.dumps(new_boat), 201)
        res.mimetype = 'application/json'
        return res

    elif request.method == 'GET':
        # get your boats
        # query parameters
        q_offset = int(request.args.get('offset', '0'))
        q_limit = int(request.args.get('limit', '5'))

        query = client.query(kind=constants.boats)
        query.add_filter("owner", "=", payload['sub'])
        l_iterator = query.fetch(offset=q_offset, limit=q_limit)
        pages = l_iterator.pages
        results = list(next(pages))

        for e in results:
            e['id'] = e.key.id
            e['self'] = request.base_url + "/" + str(e.key.id)
            if e['slip']:
                e['slip']['self'] = request.base_url.partition('boats')[0] + 'slips/' + str(e['slip']['id'])

        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?offset=" + str(next_offset) + "&limit=" + str(q_limit)
        else:
            next_url = None

        output = {'boats': results, 'next': next_url}
        res = make_response(json.dumps(output), 200)
        res.mimetype = 'application/json'
        return res


@app.route('/boats/<bid>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def boats_get_delete_put_patch(bid):
    try:
        payload = verify_jwt(request)
    except AuthError as error:
        return handle_auth_error(error)

    boats_key = client.key(constants.boats, int(bid))
    boat = client.get(key=boats_key)
    if boat:
        if boat['owner'] != payload['sub']:
            return res_error("Boat is owned by someone else.", 403)
    else:
        return res_error("No boat with this boat_id exists", 404)

    if request.method == 'GET':
        if not request.accept_mimetypes.accept_json:
            return res_error("application/json response only", 406)

        boat['id'] = boat.key.id
        boat['self'] = request.base_url
        if boat['slip']:
            boat['slip']['self'] = request.base_url.partition('boats')[0] + 'slips/' + str(boat['slip']['id'])

        res = make_response(json.dumps(boat), 200)
        res.mimetype = 'application/json'
        return res

    elif request.method == 'DELETE':
        # delete a boat

        if boat['slip'] and boat['slip']['id']:
            slips_key = client.key(constants.slips, boat['slip']['id'])
            slip = client.get(key=slips_key)
            slip['boat'] = None
            client.put(slip)

        client.delete(boats_key)
        res = make_response('', 204)
        return res

    elif request.method == 'PUT':
        # update a boat
        if not request.accept_mimetypes.accept_json:
            return res_error("application/json response only", 406)
        if not request.is_json:
            return res_error('Unsupported Media Type', 415)

        content = request.get_json()
        if "name" not in content or "type" not in content or "length" not in content:
            return res_error('The request object is missing at least one of the required attributes', 400)

        boat.update({"name": content["name"], "type": content["type"],
                     "length": content["length"]})
        client.put(boat)
        boat['id'] = boat.key.id
        boat['self'] = request.base_url
        if boat['slip']:
            boat['slip']['self'] = request.base_url.partition('boats')[0] + 'slips/' + str(boat['slip']['id'])

        res = make_response(json.dumps(boat), 200)
        res.mimetype = 'application/json'
        return res

    elif request.method == 'PATCH':
        if not request.accept_mimetypes.accept_json:
            return res_error("application/json response only", 406)
        if not request.is_json:
            return res_error('Unsupported Media Type', 415)

        content = request.get_json()
        if "name" not in content and "type" not in content and "length" not in content:
            return res_error("The request object is missing at least one of the required attributes", 400)

        attr = ("name", "type", "length")
        attr = [attr[i] for i in range(len(attr)) if attr[i] in content]
        for x in attr:
            boat[x] = content[x]
        client.put(boat)
        boat['id'] = boat.key.id
        boat['self'] = request.base_url
        if boat['slip']:
            boat['slip']['self'] = request.base_url.partition('boats')[0] + 'slips/' + str(boat['slip']['id'])

        res = make_response(json.dumps(boat), 200)
        res.mimetype = 'application/json'
        return res


@app.route('/slips', methods=['POST', 'GET'])
def slips_post_get():

    if not request.accept_mimetypes.accept_json:
        return res_error("application/json response only", 406)

    if request.method == 'POST':

        content = request.get_json()
        if "harbor" not in content or "depth" not in content or "rate" not in content:
            return res_error('The request object is missing at least one of the required attributes', 400)

        new_slip = datastore.entity.Entity(key=client.key(constants.slips))
        new_slip.update({"harbor": content["harbor"], "depth": content["depth"],
                         "rate": content["rate"], "boat": None})
        client.put(new_slip)
        new_slip['id'] = new_slip.key.id
        new_slip['self'] = request.base_url + "/" + str(new_slip.key.id)
        res = make_response(json.dumps(new_slip), 201)
        res.mimetype = 'application/json'
        return res

    elif request.method == 'GET':
        # get your slips
        q_offset = int(request.args.get('offset', '0'))
        q_limit = int(request.args.get('limit', '5'))
        query = client.query(kind=constants.slips)
        query_iter = query.fetch(offset=q_offset, limit=q_limit)

        results = list(next(query_iter.pages))
        for e in results:
            e['id'] = e.key.id
            e['self'] = request.base_url + "/" + str(e.key.id)
            if e['boat']:
                e['boat']['self'] = request.base_url.partition('slips')[0] + 'boats/' + str(e['boat']['id'])

        if query_iter.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?offset=" + str(next_offset) + "&limit=" + str(q_limit)
        else:
            next_url = None
        output = {'slips': results, 'next': next_url}

        res = make_response(json.dumps(output), 200)
        res.mimetype = 'application/json'
        return res


@app.route('/slips/<sid>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def slips_get_delete_put_patch(sid):

    slips_key = client.key(constants.slips, int(sid))
    slip = client.get(key=slips_key)
    if slip:
        if slip['boat']:
            # slip has a boat in it.

            boats_key = client.key(constants.boats, slip['boat']['id'])
            boat = client.get(key=boats_key)

            if boat:
                if request.method == 'PUT' or request.method == 'PATCH' or request.method == 'DELETE':
                    try:
                        payload = verify_jwt(request)
                    except AuthError as error:
                        return handle_auth_error(error)
                    if boat['owner'] != payload['sub']:
                        return res_error("Slip has boat owned by someone else.", 403)
            else:
                return res_error("Slip has a non-existent boat??", 404)

    else:
        # slip does not exist.
        return res_error("No slip with this slip_id exists", 404)

    if request.method == 'GET':
        if not request.accept_mimetypes.accept_json:
            return res_error("application/json response only", 406)

        slip['id'] = slip.key.id
        slip['self'] = request.base_url
        if slip['boat']:
            slip['boat']['self'] = request.base_url.partition('slips')[0] + 'boats/' + str(slip['boat']['id'])
        res = make_response(json.dumps(slip), 200)
        res.mimetype = 'application/json'
        return res

    elif request.method == 'DELETE':
        if slip['boat']:
            boat.update({'slip': None})
            client.put(boat)

        client.delete(slips_key)
        res = make_response('', 204)
        return res

    elif request.method == 'PUT':
        if not request.accept_mimetypes.accept_json:
            return res_error("application/json response only", 406)
        if not request.is_json:
            return res_error('Unsupported Media Type', 415)

        content = request.get_json()
        if "harbor" not in content or "depth" not in content or "rate" not in content:
            return res_error('The request object is missing at least one of the required attributes', 400)

        slip.update({"harbor": content["harbor"], "depth": content["depth"],
                     "rate": content["rate"]})
        client.put(slip)
        slip['id'] = slip.key.id
        slip['self'] = request.base_url
        if slip['boat']:
            slip['boat']['self'] = request.base_url.partition('slips')[0] + 'boats/' + str(slip['boat']['id'])

        res = make_response(json.dumps(slip), 200)
        res.mimetype = 'application/json'
        return res

    elif request.method == 'PATCH':
        if not request.accept_mimetypes.accept_json:
            return res_error("application/json response only", 406)
        if not request.is_json:
            return res_error('Unsupported Media Type', 415)

        content = request.get_json()
        if "harbor" not in content and "depth" not in content and "rate" not in content:
            return res_error("The request object is missing at least one of the required attributes", 400)

        attr = ("harbor", "depth", "rate")
        attr = [attr[i] for i in range(len(attr)) if attr[i] in content]

        for x in attr:
            slip[x] = content[x]
        client.put(slip)
        slip['id'] = slip.key.id
        slip['self'] = request.base_url
        if slip['boat']:
            slip['boat']['self'] = request.base_url.partition('slips')[0] + 'boats/' + str(slip['boat']['id'])
        res = make_response(json.dumps(slip), 200)
        res.mimetype = 'application/json'
        return res


@app.route('/slips/<sid>/boats/<bid>', methods=['PUT', 'DELETE'])
def slips_boats_put_delete(sid, bid):
    try:
        payload = verify_jwt(request)
    except AuthError as error:
        return handle_auth_error(error)

    boats_key = client.key(constants.boats, int(bid))
    boat = client.get(key=boats_key)
    if boat:
        if boat['owner'] != payload['sub']:
            return res_error("Boat is owned by someone else.", 403)
    else:
        return res_error("No boat with this boat_id exists", 404)

    slips_key = client.key(constants.slips, int(sid))
    slip = client.get(key=slips_key)
    if not slip:
        return res_error("No slip with this slip_id exists", 404)

    if request.method == 'PUT':
        if slip["boat"]:
            return res_error("The slip is not empty or boat is already at slip",403)

        slip["boat"] = {"id": int(bid)}
        client.put(slip)

        if boat['slip'] and boat['slip']['id']:
            old_slips_key = client.key(constants.slips, boat['slip']['id'])
            old_slip = client.get(key=old_slips_key)
            if old_slip:
                old_slip['boat'] = None
                client.put(old_slip)

        boat["slip"] = {"id": int(sid)}
        client.put(boat)
        res = make_response('', 204)
        return res

    elif request.method == 'DELETE':
        if not slip['boat'] or slip["boat"]['id'] != int(bid):
            return res_error("No boat with this boat_id is at the slip with this slip_id",404)

        slip["boat"] = None
        client.put(slip)
        boat["slip"] = None
        client.put(boat)
        res = make_response('', 204)
        return res


def delete_everything():
    # everything except users.
    cons = (constants.boats, constants.slips)
    for x in cons:
        query = client.query(kind=x)
        results = list(query.fetch())
        for e in results:
            client.delete(e.key)


@app.route('/reset', methods=['DELETE'])
def reset_boats():
    # secret delete everything button.
    delete_everything()
    return ('',204)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)