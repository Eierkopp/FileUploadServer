#!/usr/bin/python3

import argparse
import base64
import json
import logging
from logging.config import dictConfig
import mimetypes
import os
import socket
import ssl
import types
from functools import wraps
from django.utils import text
from flask import Flask, request, Response, render_template_string, make_response, send_file, redirect, url_for
from configparser import SafeConfigParser, ExtendedInterpolation
import werkzeug.serving

logging.basicConfig()

UNAUTH = "anonymous"
ACTIONS = [ "read", "write", "list", "delete" ]
TEMPLATE="""<!doctype html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <title>File Upload Server for {{user}}</title>
    <style>
      #head {
      border: 2px solid black;
      display: table;
      clear: both;
      width: 100%;
      }
      #msgbox {
      vertical-align: middle;
      float: left;
      width: 40%;
      }
      #loginbox {
      vertical-align: middle;
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
      .fullhr {
      width: 100%;
      float: left;
      }
    </style>
  </head>
  <div id="head">
    <div id="msgbox">
      <label>Status message: </label>
      {% if status -%}
      <p>
      {{ status }}
      <p>
      {% endif -%}
    </div>
    <p>
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
  <p>
  {% for d, d_details in files.items() -%}
  {% if d_details["access"] -%}
  <hr class="fullhr">
  <div id="dir">{{d}}</div>
  {% if "write" in d_details["access"] -%}
  <form action="/upload/file/{{d}}/" method=post enctype=multipart/form-data>
    <input type="file" name="file" />
    <button type="submit">upload</button>
  </form>
  {% endif -%}
  {% if "list" in d_details["access"] -%}
    <p>
    {% for f, f_details in d_details["files"].items() -%}
      <div id="row">
      {% if "read" in d_details["access"] -%}
      <div id="link"><a id="link" href="{{f_details['link']}}">{{f}}</a></div>
      <div id="full_link">{{f_details["prefix"]}}{{f_details['full_link']}}</div>
      {% else -%}
      {{f}}
      {% endif -%}
      {% if "delete" in d_details["access"] -%}
      <div id="delete"><a href="delete/{{f_details['full_link']}}">delete</a></div>
      {% endif -%}
      </div>
      <p>
    {% endfor -%}
    {% endif -%}
  {% endif -%}
  {% endfor -%}
  <hr class="fullhr">
</html>
"""

letsencrypt_data = None

def get_all_user(config, section, access):
    result = set()
    g_access = "%s_groups" % access
    u_access = "%s_user" % access
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
    for a in ACTIONS: u[a] = []

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
            for action in ACTIONS:
                all_user = get_all_user(config, section, action)
                for user in all_user:
                    if user not in user_perms:
                        logging.getLogger(__name__).error("User '%s' unconfigured", user)
                        continue
                    user_perms[user][action].append(dir_name)
    config.user_perms = user_perms
    config.all_dirs = all_dirs

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
    compute_permissions(config)
    return config

def setup_logging():
    log_config = json.loads(config.get("logging", "config"))
    dictConfig(log_config)

def make_server_hack(*args, **kwargs):

    def my_get_request(server):
        con, info = server.unwrapped_socket.accept()
        text_start = con.recv(4, socket.MSG_PEEK)
        if text_start not in [b"GET ", b"POST", b"HEAD", b"OPTI"]:
            con = server.ssl_context.wrap_socket(con, server_side=True)
        return con, info
    
    server = werkzeug.serving.make_server_orig(*args, **kwargs)
    server.unwrapped_socket = socket.fromfd(server.socket.fileno(), server.address_family, socket.SOCK_STREAM)
    server.get_request = types.MethodType(my_get_request, server)
    return server
            
def setup_app():
    # monkey patch server
    werkzeug.serving.make_server_orig = werkzeug.serving.make_server
    werkzeug.serving.make_server = make_server_hack
    
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
    context = (config.get("global", "certfile"),
               config.get("global", "keyfile"))
    #context = None # disable SSL
    app.run(host=config.get("global", "host"),
               port=config.getint("global", "port"),
               ssl_context=context,
               threaded=True)

config = load_config()

setup_logging()

app = setup_app()

def get_files(user):
    files = dict()
    all_files = set()
    for dir_name in config.all_dirs:
        dir_dict = files.setdefault(dir_name, {"files" : dict(),
                                               "access" : set()})
        for access in ACTIONS:
            if dir_name in config.user_perms[user][access]:
                dir_dict["access"].add(access)

        if not dir_dict["access"]:
            continue
                
        dir_path = os.path.join(config.get("global", "basedir"), dir_name)
        for f in os.listdir(dir_path):
            details = dir_dict["files"].setdefault(f, dict())
            details["path"] = os.path.join(dir_path, f)
            details["prefix"] = "http%s://%s/" % ("" if dir_name in config.user_perms[UNAUTH]["read"] else "s", request.host)
            details["full_link"] = os.path.join(dir_name, f)
            if f not in config.all_dirs and f not in all_files:
                details["link"] = f
            else:
                details["link"] = details["full_link"]
            all_files.add(f)
    return files

def get_dirs(user, access):
    return config.user_perms[user][access]

def get_user(request):
    """Get username either from cookie or basic auth header"""
    try:
        try:
            auth = base64.b64decode(request.cookies["cred"]).decode("utf8")
            user, password = auth.split(":", 1)
        except:
            auth = request.authorization
            user, password = auth["username"], auth["password"]
    
        if config.user_perms[user]["creds"] == password:
            return user
    except:
        pass
    return UNAUTH

def add_cookie(resp, user, password):
    val = "%s:%s" % (user, password)
    resp.set_cookie("cred", base64.b64encode(val.encode("utf8")).decode("ascii"))

def fetch_user_auth():
    user = request.values.get("user", None)
    password = request.values.get("password", None)
    if user:
        creds = config.user_perms.get(user,{}).get("creds", None)
        if creds == password:
            logging.getLogger(__name__).info("%s - - User %s signed in", request.remote_addr, user)
        else:
            logging.getLogger(__name__).warn("%s - - Invalid credentials %s:%s", request.remote_addr, user, password)
            user = UNAUTH
            password = ""
    return user, password

def redirect_on_exception(func):
    @wraps(func)
    def __wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            logging.getLogger(__name__).error("Error in function", exc_info=True)
            return redirect("/", code=302)
    return __wrapper

@app.route("/favicon.ico", methods=["GET"])
def favicon():
    favicon = 'AAABAAEAEBAQjwAAAACoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAACAAAAAgIAAgAAAAIAAgACAgAAAgICAAMDAwAAAAP8AAP8AAAD//wD/AAAA/wD/AP//AAD///8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4h3AAAAAACIiI8AAAAAAI+I+AAAAAAAAAAAAAAAAAAId4AAAAAAAH939wAAAAAAdwB3AAAAAAAQAAEAAAAAALMAOwAAAAAAMAADAAAAAAAQAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    return Response(base64.b64decode(favicon), mimetype="image/gif")

@app.route("/.well-known/acme-challenge/<key>", methods=["GET"])
def serve_letsencrypt(key):
    logging.getLogger(__name__).info("%s - - letsencrypt verification request %s", request.remote_addr, key)
    if letsencrypt_data:
        return Response(letsencrypt_data, 200)
    else:
        return Response("permission denied", 403)

@app.route("/.well-known/acme-challenge/upload/<key>", methods=["GET"])
def upload_letsencrypt(key):
    logging.getLogger(__name__).info("%s - - letsencrypt verification file upload %s", request.remote_addr, key)
    global letsencrypt_data
    letsencrypt_data = key
    return Response("ok", 200)

@app.route("/upload/file/<directory>/", methods=["POST"])
@redirect_on_exception
def upload_file(directory):
    user = get_user(request)
    files = get_files(user)
    if "write" not in files[directory]["access"]:
        return Response("permission denied", 403)
    file = request.files['file']
    fname = text.get_valid_filename(file.filename)
    name = os.path.join(directory, fname)
    fullname = os.path.join(config.get("global","basedir"), name)
    if not fname:
        return redirect(url_for("list_root", status="invalid filename"), code=302) 
    if fname in files[directory]["files"]:
        return Response("duplicate", 403)
    file.save(fullname)
    logging.getLogger(__name__).info("%s - - File %s uploaded by %s", request.remote_addr, name, user)
    size = os.stat(fullname).st_size
    return redirect(url_for("list_root", status="%d bytes saved as %s" % (size, fname)),
                    code=302)
    
@app.route("/delete/<dirname>/<filename>", methods=["GET"])
@redirect_on_exception
def delete_file_from_dir(dirname, filename):
    user = get_user(request)
    files = get_files(user)
    name = os.path.join(dirname, filename)
    for d, d_details in files.items():
        if "delete" not in d_details["access"]:
            continue
        for f, f_details in d_details["files"].items():
            if f_details["full_link"] == name:
                os.remove(f_details["path"])
                logging.getLogger(__name__).info("%s - - File %s deleted by %s", request.remote_addr, name, user)
                return redirect(url_for("list_root", status="Fle %s deleted" % name),
                                code=302)
    return Response("permission denied", 403)

@app.route("/<dirname>/<filename>", methods=["GET"])
@redirect_on_exception
def download_file_from_dir(dirname, filename):
    return download_file(os.path.join(dirname, filename))

def get_mime_type(f):
    type = mimetypes.guess_type(f, strict=False)[0]
    return type if type is not None else "application/octet-stream"

@app.route("/<filename>", methods=["GET"])
@redirect_on_exception
def download_file(filename):
    user = get_user(request)
    files = get_files(user)
    for d, d_details in files.items():
        if "read" not in d_details["access"]:
            continue
        for f, f_details in d_details["files"].items():
            if filename in [f_details["link"], f_details["full_link"]]:
                logging.getLogger(__name__).info("%s - - File %s downloaded by %s", request.remote_addr, f_details["full_link"], user)
                return send_file(f_details["path"], mimetype=get_mime_type(f))
    return Response("permission denied", 403)

@app.route("/", methods=["GET", "POST"])
@redirect_on_exception
def list_root():
    new_user, passwd = fetch_user_auth()
    status = request.values.get("status", None)
    if new_user:
        user = new_user
    else:
        user = get_user(request)
        
    files = get_files(user)

    resp = Response(render_template_string(TEMPLATE,
                                           files=files,
                                           status=status,
                                           user=user))
    if new_user:
        add_cookie(resp, user, passwd)
    return resp

run_server(app)



