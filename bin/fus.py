#!/usr/bin/python3

import argparse
import base64
from enum import Enum
import json
import logging
from logging.config import dictConfig
import mimetypes
import os
from pprint import pprint
import socket
import stat
import types
from functools import wraps

import gevent
from gevent.pywsgi import WSGIServer

from django.utils import text
from flask import Flask, request, Response, render_template_string, make_response, send_file, redirect, url_for
from configparser import SafeConfigParser, ExtendedInterpolation
import werkzeug.serving

class Access(Enum):
    LIST = "list"
    FETCH = "read"
    DELETE = "delete"
    UPLOAD = "write"
    MKDIR = "mkdir"

logging.basicConfig()

UNAUTH = "anonymous"

TEMPLATE="""<!doctype html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <title>File Upload Server for {{user}}</title>
    <style>
      #head {
      border: 2px solid black;
      overflow: hidden:
      position: relative;
      display: table;
      clear: both;
      width: 100%;
      }
      #msgbox {
      vertical-align: top;
      float: left;
      }
      #loginbox {
      vertical-align: top;
      float: right;
      }
      a {
      color: blue;
      }
      #dir {
      width:100%;
      float: left;
      }
      #row {
      display: block;
      width: 95%;
      margin-left: 2%;
      float: left;
      }
      #link {
      width: 40%;
      float: left;
      }
      #full_link {
      width: 40%;
      float: left;
      }
      #delete {
      width: 5%;
      float: right;
      }
      #content {
      }
      .fullhr {
      width: 100%;
      float: left;
      }
      .linkbutton {
      background:none!important;
      color:blue;
      border:none; 
      padding:0!important;
      font: inherit;
      border-bottom:1px solid #444; 
      cursor: pointer;
      }
    </style>
  </head>
  <div id="head">
    <div id="msgbox">
      {% if status -%}
      <div id="status">
        <label>Status message: </label>
        <p>
        {{ status }}
      </div>
      {% else -%}
      <div id="privacy">
        <form method="POST" action="/privacy">
          <input type="hidden" name="cred" value="{{cred}}"/>
          <button class="linkbutton" type="submit">privacy</button>
        </form>
      </div>
      {% endif -%}
    </div>
    <div id="loginbox">
      <form method="POST" action="/">
        <table>
          <tr>
            <td>
              <label>User</label>
            </td>
            <td>
              <input type="text" name="user" maxlength="30">
            </td>
          </tr>
          <tr>
            <td>
              <label>Password</label>
            </td>
            <td>
              <input type="password" name="password" maxlength="30">
            </td>
          </tr>
          <tr>
            <td>
              <button type="submit">sign in</button>
            </td>
            <td/>
          </tr>
        </table>
      </form>
    </div>
  </div>
  <div id="content">
  {% if allow_upload -%}
  <hr class="fullhr">
  <form action="/{{dirname}}?action=upload" method="post" enctype="multipart/form-data">
    <input type="file" name="file" />
    <input type="hidden" name="cred" value="{{cred}}" />
    <button type="submit">upload</button>
  </form>
  {% endif -%}
  {% if files -%}
  <hr class="fullhr">
  {% for f in files -%}
  <p>
  <div id="row">
  </div>
  {% if allow_fetch -%}
  <div id="link"><a id="link" href="{{prefix}}{{f["path"]}}">{{f["name"]}}</a></div>
  <div id="full_link">{{prefix}}{{f["path"]}}</div>
  {% else -%}
  {{f["name"]}}
  {% endif -%}
  {% if allow_delete -%}
  <form action="/{{f["path"]}}" method="post">
    <input type="hidden" name="action" value="delete" />    
    <input type="hidden" name="cred" value="{{cred}}" />
    <button type="submit">delete</button>
  </form>
  {% endif -%}
  {% endfor -%}
  {% endif -%}
  {% if subdirs or parentdir != None or allow_mkdir -%}
  <hr class="fullhr">
  {% if parentdir != None -%}
  <div id="row">
  <div id="link">
    <form method="POST" action="{{prefix}}{{parentdir}}">
    <input type="hidden" name="cred" value="{{cred}}"/>
    <button class="linkbutton">&lt;parent directory&gt;</button>
  </form>
  </div>
  {% endif -%} 
  {% if allow_mkdir -%}
  <div id="row">
  <form action="/{{dirname}}" method="POST">
    <input type="hidden" name="action" value="mkdir" />
    <input type="hidden" name="cred" value="{{cred}}"/>
    <input type="text" name="dirname" />
    <button type="submit">new directory</button>
  </form>
  </div>
  {% endif -%} 
  {% for s in subdirs -%}
  <div id="row">
  <form method="POST" action="{{prefix}}{{s["path"]}}">
    <input type="hidden" name="cred" value="{{cred}}"/>
    <button class="linkbutton">{{s["name"]}}</button>
  </form>
  </div>
  {% endfor -%}
  <hr class="fullhr">
  {% endif -%}
  </div>
</html>
"""

class AccessError(Exception):

    def __init__(self, code, message):
        super().__init__(self, message, code)

letsencrypt_data = dict()

def get_all_user(config, section, access):
    result = set()
    g_access = "%s_groups" % access.value
    u_access = "%s_user" % access.value
    groups = config.getlist(section, g_access) if config.has_option(section, g_access) else []
    group_sections = ["group:" + s for s in groups]
    for gs in group_sections:
        if not config.has_section(gs):
            logging.getLogger(__name__).error("No section '%s'", gs)
            continue
        result.update(set(config.getlist(gs, "user")))
    if config.has_option(section, u_access):
        result.update(set(config.getlist(section, u_access)))
    return result

def init_actions(perms, user):
    u = perms.setdefault(user, dict())
    for i in Access:
        u[i] = []

def compute_permissions(config):

    def mk_creds(config, section):
        if config.has_option(section, "password"):
            return config.get(section, "password")
        else:
            return base64.b64decode(config.get(section, "b64_password")).decode("utf8")
    
    user_perms = { UNAUTH: { "creds" : None } }
    init_actions(user_perms, UNAUTH)
        
    for section in config.sections():
        if section.startswith("user:"):
            user = section[5:]
            user_perms[user] = { "creds" : mk_creds(config, section) }
            init_actions(user_perms, user)

    all_dirs = set()
    for section in config.sections():
        if section.startswith("dir:"):
            dir_name = section[4:]
            all_dirs.add(dir_name)
            for access in Access:
                all_user = get_all_user(config, section, access)
                for user in all_user:
                    if user not in user_perms:
                        logging.getLogger(__name__).error("User '%s' unconfigured", user)
                        continue
                    user_perms[user][access].append(dir_name)
    config.user_perms = user_perms
    config.all_dirs = list(all_dirs)
    config.all_dirs.sort()

def load_config():

    def get_list(conf, section, option, **kwargs):
        value = conf.get(section, option, **kwargs).strip()
        return [x.strip() for x in value.split(",")] if value else []
    
    parser = argparse.ArgumentParser(prog='file upload server')
    parser.add_argument("--config",
                    help="configuration file location",
                    dest="config",
                    default="/etc/fus.conf")

    args = parser.parse_args()

    config = SafeConfigParser(interpolation=ExtendedInterpolation())
    config.getlist = types.MethodType(get_list, config)
    config.read(args.config)
    # normalize basedir
    config.set("global", "basedir", os.path.abspath(config.get("global","basedir")))
    
    compute_permissions(config)
    return config

def setup_logging():
    log_config = json.loads(config.get("logging", "config"))
    dictConfig(log_config)
            
def setup_app(): 
    # create data dirs, if needed
    basedir = config.get("global", "basedir")
    for section in config.sections():
        if section.startswith("dir:"):
            dir_name = os.path.join(basedir, section[4:])
            if not os.access(dir_name, os.R_OK | os.X_OK | os.W_OK):
                os.makedirs(dir_name)
            
    app = Flask(__name__)
    app.config['DEBUG'] = config.getboolean("global", "debug")
    return app

def run_server(app):
    server = []
    if config.has_option("global", "https_port"):
        https_server = WSGIServer((config.get("global", "host"), config.getint("global", "https_port")),
                                      app,
                                      keyfile=config.get("global", "keyfile"),
                                      certfile=config.get("global", "certfile"))
        https_server.start()
        server.append(https_server)

    if config.has_option("global", "http_port"):
        http_server = WSGIServer((config.get("global", "host"), config.getint("global", "http_port")),
                                     app)
        http_server.start()
        server.append(http_server)
        
    return server
    
config = load_config()

setup_logging()

app = setup_app()

def get_user_from_request():
    try:
        # form keys first
        user = request.values.get("user", None)
        password = request.values.get("password", None)
        
        if user is not None and password is not None:
            return user, password

        # basic-auth second
        auth = request.authorization
        if auth:
            return auth["username"], auth["password"]

        # credentials from cred form key
        cred = request.values.get("cred", None)
        if cred:
            return base64.b64decode(cred).decode("utf8").split(":", 1)
    except:
        pass
    return UNAUTH, None

def get_user():
    """Get username either from cookie, basic auth header, or form keys"""

    user, password = get_user_from_request()

    if config.user_perms.get(user, dict()).get("creds", None) == password:
        logging.getLogger(__name__).info("%s - - User %s active", request.remote_addr, user)
        cred = base64.b64encode(("%s:%s" % (user, password)).encode("ascii")).decode("ascii")
        return user, password, cred
    
    logging.getLogger(__name__).warn("%s - - Anonymous active %s:%s", request.remote_addr, user, password)
    return UNAUTH, None, ""

def redirect_on_exception(func):
    @wraps(func)
    def __wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AccessError as e:
            logging.getLogger(__name__).error("AccessError in function")
            return Response(e.args[1], e.args[2], mimetype="text/plain")# e.args[0], str(e.args[1]), mimetype="text/plain")
        except:
            logging.getLogger(__name__).error("Error in function", exc_info=True)
            return redirect("/", code=302)
    return __wrapper

@app.route("/favicon.ico", methods=["GET"])
def favicon():
    favicon = 'AAABAAEAEBAQjwAAAACoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAACAAAAAgIAAgAAAAIAAgACAgAAAgICAAMDAwAAAAP8AAP8AAAD//wD/AAAA/wD/AP//AAD///8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4h3AAAAAACIiI8AAAAAAI+I+AAAAAAAAAAAAAAAAAAId4AAAAAAAH939wAAAAAAdwB3AAAAAAAQAAEAAAAAALMAOwAAAAAAMAADAAAAAAAQAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    return Response(base64.b64decode(favicon), mimetype="image/gif")

@app.route("/.well-known/acme-challenge/<token>", methods=["GET"])
def serve_letsencrypt(token):
    logging.getLogger(__name__).info("%s - - letsencrypt verification request %s", request.remote_addr, token)
    if token in letsencrypt_data:
        return Response(letsencrypt_data[token], 200, mimetype="text/plain")
    else:
        return Response("permission denied", 403, mimetype="text/plain")

@app.route("/.well-known/acme-challenge/upload/<token>/<thumb>", methods=["GET"])
def upload_letsencrypt(token, thumb):
    logging.getLogger(__name__).info("%s - - letsencrypt verification file upload %s.%s", request.remote_addr, token, thumb)
    global letsencrypt_data
    letsencrypt_data[token] = "%s.%s" % (token, thumb)
    return Response("ok", 200, mimetype="text/plain")

def upload_file(user, cred, directory):
    file = request.files['file']
    fname = text.get_valid_filename(os.path.basename(file.filename))
    name = os.path.join(directory, fname)
    fullname = os.path.join(config.get("global","basedir"), name)
    if not fname:
        return redirect(url_for("handle", cred=cred, path=directory, status="invalid filename"), code=302) 
    if os.access(fullname, os.R_OK):
        return Response("duplicate", 403)
    file.save(fullname)
    logging.info("%s - - File %s uploaded by %s", request.remote_addr, name, user)
    size = os.lstat(fullname).st_size
    return redirect(url_for("handle", cred=cred, path=directory, status="%d bytes saved as %s" % (size, fname)),
                    code=302)
    
def delete_file(user, cred, dirname, filename):
    name = os.path.join(dirname, filename)
    fullname = os.path.join(config.get("global","basedir"), name)
    try:
        os.remove(fullname)
        logging.getLogger(__name__).info("%s - - File %s deleted by %s", request.remote_addr, fullname, user)
        return redirect(url_for("handle", cred=cred, path=dirname, status="File %s deleted" % name),
                                code=302)
    except:
        logging.error("%s - - Failed to delete %s by %s", request.remote_addr, fullname, user)
    return Response("permission denied", 403)

def make_dir(user, cred, dirname):
    filename = fname = text.get_valid_filename(request.values["dirname"])
    name = os.path.join(dirname, filename)
    fullname = os.path.join(config.get("global","basedir"), name)
    try:
        os.makedirs(fullname)
        logging.getLogger(__name__).info("%s - - Directory %s created by %s", request.remote_addr, fullname, user)
        return redirect(url_for("handle", cred=cred, path=dirname, status="Directory %s created" % name),
                                code=302)
    except:
        logging.error("%s - - Failed to create directory %s by %s", request.remote_addr, fullname, user)
    return Response("permission denied", 403)

def get_mime_type(f):
    type = mimetypes.guess_type(f, strict=False)[0]
    return type if type is not None else "application/octet-stream"

def normalize_path(path):
    basedir = config.get("global", "basedir")
    name = os.path.abspath(os.path.join(basedir, path))
    path = name[len(basedir):].strip(os.path.sep)
    
    if name != basedir and not name.startswith(basedir + os.path.sep):
        logging.warn("Outside base: %s", name)
        raise AccessError(403, "forbidden")
    try:
        
        sr = os.stat(name)
    except FileNotFoundError:
        logging.warn("File not found: %s", name)
        raise AccessError(403, "forbidden")
    except:
        logging.error("Stat error on %s", name)
        raise AccessError(403, "forbidden")

    if sr.st_uid != os.geteuid():
        logging.warn("Wrong owner found for %s", name)
    
    if stat.S_ISDIR(sr.st_mode):
        return name, path, None

    if stat.S_ISREG(sr.st_mode):
        dirname, fname = os.path.split(path)
        return name, dirname, fname

    raise AccessError(403, "forbidden")

def has_access(user, dirname, action):
    perms = config.user_perms.get(user, None)
    if perms is None:
        logging.error("Unknown user: %s", user)
        raise AccessError(403, "forbidden")

    dirs = perms.get(action, None)
    if dirs is None:
        logging.error("Unknown action: %s", action)
        raise AccessError(403, "forbidden")

    while True:
        if dirname in config.all_dirs:
            return dirname in dirs
        if len(dirname) == 0 or dirname == os.path.sep:
            return False
        dirname, _ = os.path.split(dirname)
        
def list_dir(dirname):
    names = os.listdir(dirname)
    dirs = []
    files = []
    for n in names:
        try:
            if n.startswith("."):
                continue
            sr = os.stat(os.path.join(dirname, n))
            if sr.st_uid != os.geteuid():
                continue
            if stat.S_ISDIR(sr.st_mode):
                dirs.append(n)
            if stat.S_ISREG(sr.st_mode):
                files.append(n)
        except:
            logging.exception("Error in list_dir(%s)", dirname)
    return dirs, files

def filter_file_list(user, dirname, subdirs, files):
    files.sort()
    subdirs.sort()
    if not has_access(user, dirname, Access.LIST):
        files.clear()
    
    for d in subdirs[:]:
        if not (has_access(user, os.path.join(dirname,d), Access.LIST)
                    or has_access(user, os.path.join(dirname,d), Access.UPLOAD)
                    or has_access(user, os.path.join(dirname,d), Access.MKDIR)):
            subdirs.remove(d)

def mk_prefix():
    return "http%s://%s/" % ("s" if request.is_secure else "", request.host)

@app.route("/privacy", methods=["POST"])
def privacy():
    user, password, cred = get_user()
    return redirect(url_for("handle", path="", cred=cred, status="This server does not log or store any personal data."), code=302) 

@app.route('/', defaults={'path': ''}, methods=["GET", "POST"])
@app.route('/<path:path>', methods=["GET", "POST"])
@redirect_on_exception
def handle(path):
    user, password, cred = get_user()

    fullname, dirname, fname = normalize_path(path)

    action = request.values.get("action", None)
    
    if fname is None and action in [ None, "list"]:
        if not (has_access(user, dirname, Access.LIST)
                    or has_access(user, dirname, Access.UPLOAD)
                    or has_access(user, dirname, Access.MKDIR)):
            raise AccessError(403, "forbidden")
        
        subdirs, files = list_dir(fullname)
        filter_file_list(user, dirname, subdirs, files)
        status = request.values.get("status", None)
        resp = Response(
            render_template_string(
                TEMPLATE,
                dirname=dirname,
                parentdir=None if not dirname else os.path.split(dirname)[0],
                prefix=mk_prefix(),
                files=[ { "name" : f, "path" : os.path.join(dirname, f) } for f in files],
                subdirs=[ { "name" : s, "path" : os.path.join(dirname, s) } for s in subdirs],
                status=status,
                allow_upload=has_access(user, dirname, Access.UPLOAD),
                allow_delete=has_access(user, dirname, Access.DELETE),
                allow_fetch=has_access(user, dirname, Access.FETCH),
                allow_mkdir=has_access(user, dirname, Access.MKDIR),
                user=user,
                cred=cred))

    elif fname is None and action == "upload":
        if has_access(user, dirname, Access.UPLOAD):
            resp = upload_file(user, cred, dirname)
        else:
            raise AccessError(403, "forbidden")

    elif fname and action == "delete":
        if has_access(user, dirname, Access.DELETE):
            resp = delete_file(user, cred, dirname, fname)
        else:
            raise AccessError(403, "forbidden")

    elif fname is None and action == "mkdir":
        if has_access(user, dirname, Access.MKDIR):
            resp = make_dir(user, cred, dirname)
        else:
            raise AccessError(403, "forbidden")

    elif fname and action is None:
        if has_access(user, dirname, Access.FETCH):
            logging.getLogger(__name__).info("%s - - Download %s by %s", request.remote_addr, fullname, user)
            resp = send_file(fullname, mimetype=get_mime_type(fullname))
            resp.make_conditional(request)
        else:
            raise AccessError(403, "forbidden")
    
    return resp

server = run_server(app)

while True:
    gevent.sleep(60)

#app.run(host="127.0.0.1", port=config.getint("global", "http_port"), debug=True)

