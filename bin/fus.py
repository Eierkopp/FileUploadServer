#!/usr/bin/python3

from aiohttp import web
from aiohttp.web_runner import AppRunner, TCPSite
import argparse
import asyncio
import base64
from cryptography.fernet import Fernet
from enum import Enum
from http import HTTPStatus
import jinja2
import json
import logging
from logging.config import dictConfig
import mimetypes
import os
import ssl
import stat
import threading
import types
from functools import wraps

from django.utils import text

try:
    from pyftpdlib.authorizers import AuthenticationFailed
    from pyftpdlib.filesystems import AbstractedFS, FilesystemError
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer

except ModuleNotFoundError:
    AbstractedFS = object

from configparser import ConfigParser, ExtendedInterpolation, NoOptionError


class Access(Enum):
    LIST = "list"
    FETCH = "read"
    DELETE = "delete"
    UPLOAD = "write"
    MKDIR = "mkdir"


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger

UNAUTH = "anonymous"

TEMPLATE = """<!doctype html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <title>File Upload Server for {{user}}</title>
    <style>
      #head {
      overflow: hidden:
      position: relative;
      display: grid;
      grid-template-columns: 1fr auto;
      width: 100%;
      }
      #msgbox {
      vertical-align: top;
      float: left;
      border: 1px solid black;
      }
      #loginbox {
      vertical-align: top;
      float: right;
      border: 1px solid black;
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
      {% if statusmessage -%}
      <div id="status">
        <label>Status message: </label>
        <p>
        {{ statusmessage }}
      </div>
      {% else -%}
      <div id="privacy">
        <a href="{{bp(user, dirname)}}privacy/{{dirname}}">privacy</a>
      </div>
      {% endif -%}
    </div>
    <div id="loginbox">
      <form method="POST" action="/login" >
        <table>
          <tr>
            <td>
              <label>User</label>
            </td>
            <td>
              <input type="text" name="user"  value="{{user}}" maxlength="30">
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
            <td colspan="2">
              <button type="submit">sign in</button>
            </td>
          </tr>
        </table>
      </form>
    </div>
  </div>
  <div id="content">
  {% if allow_upload -%}
  <hr class="fullhr">
  <form action="{{bp(user, dirname)}}{{dirname}}?action=upload" method="post" enctype="multipart/form-data">
    <input type="file" name="file" />
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
  <div id="link">
    <a href="{{bp(user, f["path"])}}{{f["path"]}}">
      {{f["name"]}}
    </a>
  </div>
  {% else -%}
  {{f["name"]}}
  {% endif -%}
  {% if allow_delete -%}
  <form action="{{bp(user,f["path"])}}{{f["path"]}}?action=delete" method="post">
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
    <a href="{{bp(user,parentdir)}}{{parentdir}}">
      &lt;parent directory&gt;
    </a>
  </div>
  {% endif -%}
  {% if allow_mkdir -%}
  <div id="row">
  <form action="{{bp(user,dirname)}}{{dirname}}?action=mkdir" method="POST">
    <input type="text" name="dirname" />
    <button type="submit">new directory</button>
  </form>
  </div>
  {% endif -%}
  {% for s in subdirs -%}
  <div id="row">
  <a href="{{bp(user,s["path"])}}{{s["path"]}}">
    {{s["name"]}}
  </a>
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


def redirect_on_exception(func):
    @wraps(func)
    async def __wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except web.HTTPFound:
            raise
        except AccessError as e:
            code = e.args[2]
            log(__name__).error("AccessError in function")
            if code == 401:
                return web.Response(text='Unauthorized',
                                    status=401,
                                    headers={'WWW-Authenticate': 'Basic realm="fus login"'}
                                    )
            else:
                return web.Response(text=e.args[1], status=code)
        except Exception as e:
            log(__name__).error("Error in function: %s", e)
            log(__name__).debug("Error in function", exc_info=True)
            return web.HTTPFound("/")
    return __wrapper


def get_all_user(config, section, access):
    result = set()
    g_access = "%s_groups" % access.value
    u_access = "%s_user" % access.value
    if config.has_option(section, g_access):
        groups = config.getlist(section, g_access)
    else:
        groups = []
    group_sections = ["group:" + s for s in groups]
    for gs in group_sections:
        if not config.has_section(gs):
            log(__name__).error("No section '%s'", gs)
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
            bytebuf = base64.b64decode(config.get(section, "b64_password"))
            return bytebuf.decode("utf8")

    user_perms = {UNAUTH: {"creds": None}}
    init_actions(user_perms, UNAUTH)

    for section in config.sections():
        if section.startswith("user:"):
            user = section[5:]
            user_perms[user] = {"creds": mk_creds(config, section)}
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
                        log(__name__).error("User '%s' unconfigured", user)
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

    config = ConfigParser(interpolation=ExtendedInterpolation())
    config.getlist = types.MethodType(get_list, config)
    config.read(args.config)
    # normalize basedir
    config.set("global", "basedir",
               os.path.abspath(config.get("global", "basedir")))

    compute_permissions(config)
    return config


def setup_logging(config):
    log_config = json.loads(config.get("logging", "config"))
    dictConfig(log_config)


class WebIF(object):

    def __init__(self, loop, config):
        self.loop = loop
        self.config = config
        if config.has_option("global", "key"):
            self.fernet = Fernet(config.get("global", "key"))
        else:
            log(__name__).error("You need to add a key to section [global], e.g.\n"
                                "key: %s", Fernet.generate_key().decode("ascii"))
            raise NoOptionError("key", "global")

        # create data dirs, if needed
        basedir = config.get("global", "basedir")
        for section in config.sections():
            if section.startswith("dir:"):
                dir_name = os.path.join(basedir, section[4:])
                os.makedirs(dir_name, exist_ok=True)

        self.app = web.Application()
        router = self.app.router
        router.add_route('GET', "/favicon.ico", self.favicon)
        router.add_route('POST', "/login", self.login)
        router.add_route('GET', "/.well-known/acme-challenge/{token}",
                         self.serve_letsencrypt)
        router.add_route('GET', "/.well-known/acme-challenge/upload/{token}/{thumb}",
                         self.upload_letsencrypt)
        router.add_route('GET', "/privacy", self.privacy)
        router.add_route('GET', "/{token}/auth/privacy", self.privacy)
        router.add_route('GET', "/{token}/auth/privacy/{path:.*}", self.privacy)
        router.add_route('GET', "/{token}/auth/{path:.*}", self.handle)
        router.add_route('POST', "/{token}/auth/{path:.*}", self.handle)
        router.add_route('GET', "/{path:.*}", self.handle, name='handle-get')
        router.add_route('POST', "/{path:.*}", self.handle, name='handle-post')

        self.runner = AppRunner(self.app)
        self.loop.run_until_complete(self.runner.setup())
        self.cert_watcher = None

        loop.run_until_complete(self.init_site("http_site"))
        loop.run_until_complete(self.init_site("https_site"))

        self.letsencrypt_data = dict()

    async def init_site(self, site_name):
        if getattr(self, site_name, None):
            await getattr(self, site_name).stop()

        if site_name == "https_site":
            if not self.config.has_option("global", "https_port"):
                return
            port = self.config.getint("global", "https_port")
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            ssl_context.load_cert_chain(certfile=config.get("global", "certfile"),
                                        keyfile=config.get("global", "keyfile"))
            if self.cert_watcher is None:
                self.cert_watcher = loop.create_task(self.watch_cert())
        else:
            if not self.config.has_option("global", "http_port"):
                return
            port = self.config.getint("global", "http_port")
            ssl_context = None

        log(__name__).info("Starting fresh site %s on port %d", site_name, port)

        site = TCPSite(self.runner,
                       config.get("global", "host"),
                       port,
                       ssl_context=ssl_context,
                       reuse_address=True,
                       reuse_port=True)

        setattr(self, site_name, site)
        await site.start()

    def close(self):
        self.loop.run_until_complete(self.runner.cleanup())
        if self.cert_watcher:
            self.cert_watcher.cancel()

    async def watch_cert(self):

        def get_mtime(fname, old_mtime):
            try:
                return os.stat(fname).st_mtime
            except OSError:
                log(__name__).debug("Error in stat", exc_info=True)
                return old_mtime

        fname = self.config.get("global", "certfile")
        ts = get_mtime(fname, None)
        while True:
            await asyncio.sleep(5)
            new_ts = get_mtime(fname, ts)
            if new_ts != ts:
                ts = new_ts
                await self.init_site("https_site")
                log(__name__).debug("Updated ssl context")

    def peername(self, request):
        peername = request.transport.get_extra_info('peername')
        return peername if peername else ("???", 0)

    def redirect(self, request, user, path, msg):
        router = request.app.router['handle-get']
        if path is None:
            path = ""
        path = (self.build_prefix(user, path) + path).lstrip("/")
        if msg is None:
            raise web.HTTPFound(router.url_for(path=path))
        else:
            raise web.HTTPFound(router.url_for(path=path).with_query({"msg": msg}))

    async def favicon(self, request):
        favicon = self.config.get("global", "favicon")
        return web.Response(body=base64.b64decode(favicon), content_type="image/vnd.microsoft.icon")

    async def serve_letsencrypt(self, request):
        token = request.match_info["token"]
        log(__name__).info("%s - - cert verification request %s", self.peername(request), token)
        if token in self.letsencrypt_data:
            return web.Response(text=self.letsencrypt_data[token], status=200)
        else:
            return web.Response(text="permission denied", status=403, reason="permission denied")

    async def upload_letsencrypt(self, request):
        token = request.match_info["token"]
        thumb = request.match_info["thumb"]
        log(__name__).info("%s - - cert verification file %s.%s",
                           self.peername(request), token, thumb)
        self.letsencrypt_data[token] = "%s.%s" % (token, thumb)
        return web.Response(text="ok", status=200)

    async def get_user(self, request):
        """Get username either from token, basic auth header, or form keys"""

        user, password = await self.get_user_from_request(request)

        if self.config.user_perms.get(user, dict()).get("creds", None) == password:
            log(__name__).info("%s - - User %s active", self.peername(request), user)
            cred = ("%s:%s" % (user, password)).encode("ascii")
            cred = base64.b64encode(cred).decode("ascii")
            return user, password, cred

        log(__name__).warning("%s - - Anonymous active %s:%s",
                              self.peername(request), user, password)
        return UNAUTH, None, ""

    async def get_user_from_request(self, request):
        try:
            if request.content_type == "application/x-www-form-urlencoded":
                formdata = await request.post()
                request.formdata = formdata
            else:
                request.formdata = dict()

            # form keys first
            user = request.formdata.get("user", None)
            password = request.formdata.get("password", None)
            if user is not None and password is not None:
                return user, password

            if "token" in request.match_info:
                token = request.match_info["token"].encode("ascii")
                user, path = self.fernet.decrypt(token).decode("utf-8").split(":", 1)
                if path == request.match_info["path"]:
                    return user, self.config.user_perms.get(user, dict()).get("creds", None)

            # basic-auth second
            auth = request.headers.get("authorization", "")
            if auth.lower().startswith("basic "):
                return base64.b64decode(auth[6:]).decode("utf8").split(":", 1)

        except Exception:
            log(__name__).info("Error", exc_info=True)
        return UNAUTH, None

    def build_prefix(self, user, path):
        if user == UNAUTH:
            return "/"
        else:
            token = self.fernet.encrypt(("%s:%s" % (user, path)).encode("utf-8"))
            return "/%s/auth/" % token.decode("ascii")

    @redirect_on_exception
    async def login(self, request):
        user, password, cred = await self.get_user(request)
        if user == UNAUTH:
            msg = "signed out"
        else:
            msg = "%s signed in" % user
        self.redirect(request, user, "", msg)

    @redirect_on_exception
    async def handle(self, request):
        path = request.match_info.get("path", "")
        fullname, dirname, fname = self.normalize_path(path)

        action = request.query.get("action", None)
        user, password, cred = await self.get_user(request)

        if fname is None and action in [None, "list"]:
            if not (has_access(user, dirname, Access.LIST)
                    or has_access(user, dirname, Access.UPLOAD)
                    or has_access(user, dirname, Access.MKDIR)):
                raise AccessError(HTTPStatus.UNAUTHORIZED, "forbidden")

            subdirs, files = list_dir(fullname)
            filter_file_list(user, dirname, subdirs, files)
            msg = request.query.get("msg", None)
            template = jinja2.Template(TEMPLATE)
            resp = web.Response(
                status=200,
                content_type='text/html',
                text=template.render(
                    dirname=dirname,
                    parentdir=None if not dirname else os.path.split(dirname)[0],
                    files=[{"name": f,
                            "path": os.path.join(dirname, f)}
                           for f in files],
                    subdirs=[{"name": s,
                              "path": os.path.join(dirname, s)}
                             for s in subdirs],
                    statusmessage=msg,
                    prefix="/",
                    allow_upload=has_access(user, dirname, Access.UPLOAD),
                    allow_delete=has_access(user, dirname, Access.DELETE),
                    allow_fetch=has_access(user, dirname, Access.FETCH),
                    allow_mkdir=has_access(user, dirname, Access.MKDIR),
                    debug=config.getboolean("global", "debug"),
                    user=user,
                    bp=self.build_prefix)
                )

        elif fname is None and action == "upload":
            if has_access(user, dirname, Access.UPLOAD):
                resp = await self.upload_file(request, user, dirname)
            else:
                raise AccessError(401, "forbidden")

        elif fname and action == "delete":
            if has_access(user, dirname, Access.DELETE):
                resp = await self.delete_file(request, user, dirname, fname)
            else:
                raise AccessError(401, "forbidden")

        elif fname is None and action == "mkdir":
            if has_access(user, dirname, Access.MKDIR):
                resp = await self.make_dir(request, user, dirname)
            else:
                raise AccessError(401, "forbidden")

        elif fname and action is None:
            if has_access(user, dirname, Access.FETCH):
                log(__name__).info("%s - - Download %s by %s",
                                   self.peername(request),
                                   fullname,
                                   user)
                resp = await self.streamfile(request, fullname)
            else:
                raise AccessError(401, "forbidden")

        resp.headers["Accept-Ranges"] = "bytes"
        return resp

    async def make_dir(self, request, user, dirname):
        filename = text.get_valid_filename(request.formdata["dirname"])
        name = os.path.join(dirname, filename)
        fullname = os.path.join(config.get("global", "basedir"), name)
        os.makedirs(fullname, exist_ok=True)
        log(__name__).info("%s - - Directory %s created by %s",
                           self.peername(request),
                           fullname,
                           user)
        self.redirect(request, user, dirname, "Directory %s created" % name)

    async def upload_file(self, request, user, directory):
        if request.method != "POST" or request.content_type != "multipart/form-data":
            AccessError(400, "invalid")

        reader = await request.multipart()
        field = await reader.next()
        if field.name != "file":
            AccessError(400, "invalid")
        fname = text.get_valid_filename(os.path.basename(field.filename))
        name = os.path.join(directory, fname)
        fullname = os.path.join(config.get("global", "basedir"), name)
        if not fname:
            self.redirect(request, user, directory, "invalid filename")
        if os.access(fullname, os.R_OK):
            raise AccessError(403, "duplicate")
        with open(fullname, 'wb') as f:
            while True:
                chunk = await field.read_chunk()  # 8192 bytes by default.
                if not chunk:
                    break
                f.write(chunk)
        log(__name__).info("%s - - File %s uploaded by %s",
                           self.peername(request), name, user)
        size = os.lstat(fullname).st_size
        self.redirect(request, user, directory, "%d bytes saved as %s" % (size, fname))

    async def delete_file(self, request, user, dirname, filename):
        name = os.path.join(dirname, filename)
        fullname = os.path.join(config.get("global", "basedir"), name)
        os.remove(fullname)
        log(__name__).info("%s - - File %s deleted by %s",
                           self.peername(request),
                           fullname,
                           user)
        self.redirect(request, user, dirname, "File %s deleted" % name)
        raise AccessError(401, "permission denied")

    async def streamfile(self, request, fullname):
        rng = request.http_range

        resp = web.StreamResponse(status=200 if rng.start is None else 206,
                                  reason="OK",
                                  headers={'Content-Type': get_mime_type(fullname),
                                           'Accept-Ranges': 'bytes'})

        size = length = os.path.getsize(fullname)

        try:

            with open(fullname, 'rb') as f:
                if rng.start is not None:
                    length -= rng.start
                    if rng.stop is not None:
                        length = min(rng.stop - rng.start + 1, length)
                    cr = "bytes {0}-{1}/{2}".format(rng.start, rng.start + length - 1, size)
                    resp.headers["Content-Range"] = cr
                    f.seek(rng.start)
                await resp.prepare(request)
                while length > 0:
                    buf = f.read(min(8192, length))
                    if not buf:
                        break
                    length -= len(buf)
                    await resp.write(buf)

                await resp.write_eof()
        except ConnectionResetError:
            # client went away
            pass

        return resp

    async def privacy(self, request):
        path = request.match_info.get("path", "")
        print("Path=", path)
        user, password, cred = await self.get_user(request)
        self.redirect(request, user, path, self.config.get("global", "gdprmsg"))

    def normalize_path(self, path):
        basedir = self.config.get("global", "basedir")
        name = os.path.abspath(os.path.join(basedir, path))
        path = name[len(basedir):].strip(os.path.sep)

        if name != basedir and not name.startswith(basedir + os.path.sep):
            log(__name__).warning("Outside base: %s", name)
            raise AccessError(403, "forbidden")
        try:
            sr = os.stat(name)
        except FileNotFoundError:
            log(__name__).warning("File not found: %s", name)
            raise AccessError(404, "not found")
        except Exception:
            log(__name__).error("Stat error on %s", name)
            raise AccessError(401, "forbidden")

        if sr.st_uid != os.geteuid():
            log(__name__).warning("Wrong owner found for %s", name)

        if stat.S_ISDIR(sr.st_mode):
            return name, path, None

        if stat.S_ISREG(sr.st_mode):
            dirname, fname = os.path.split(path)
            return name, dirname, fname

        raise AccessError(401, "forbidden")


def get_mime_type(f):
    type = mimetypes.guess_type(f, strict=False)[0]
    return type if type is not None else "application/octet-stream"


def has_access(user, dirname, action):
    perms = config.user_perms.get(user, None)
    if perms is None:
        log(__name__).error("Unknown user: %s", user)
        raise AccessError(401, "forbidden")

    dirs = perms.get(action, None)
    if dirs is None:
        log(__name__).error("Unknown action: %s", action)
        raise AccessError(401, "forbidden")

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
        except Exception:
            log(__name__).exception("Error in list_dir(%s)", dirname)
    return dirs, files


def filter_file_list(user, dirname, subdirs, files):
    files.sort()
    subdirs.sort()
    if not has_access(user, dirname, Access.LIST):
        files.clear()

    for d in subdirs[:]:
        path = os.path.join(dirname, d)
        if not (has_access(user, path, Access.LIST)
                or has_access(user, path, Access.UPLOAD)
                or has_access(user, path, Access.MKDIR)):
            subdirs.remove(d)


#
# FTP adapter
#


class MyAuthorizer(object):

    def validate_authentication(self, username, password, handler):
        creds = config.user_perms.get(username, dict()).get("creds", None)
        if creds != password:
            log(__name__).warning("Invalid credentials for user %s", username)
            raise AuthenticationFailed()
        log(__name__).info("User %s logged in", username)

    def get_home_dir(self, username):
        return config.get("global", "basedir")

    def get_msg_login(self, username):
        return "Welcome, %s." % username

    def get_msg_quit(self, username):
        return "Bye."

    def impersonate_user(self, username, password):
        pass

    def terminate_impersonation(self, username):
        pass

    def has_user(self, username):
        return True

    def get_perms(self, username):
        return "l"

    def has_perm(self, username, perm, path=None):
        if path and path.startswith(config.get("global", "basedir")):
            path = path[len(config.get("global", "basedir")):]
        path = path.lstrip(os.path.sep)

        if perm in "elmrwd":
            log(__name__).debug("User %s granted %s for '%s'",
                                username,
                                perm,
                                path)
            return True
        else:
            log(__name__).warning("Perm %s invalid for user %s at '%s'",
                                  perm,
                                  username,
                                  path)
        return False


class MyFilesystem(AbstractedFS):

    def strip_path(self, path):
        if path.startswith(config.get("global", "basedir")):
            path = path[len(config.get("global", "basedir")):]
        return path.lstrip(os.path.sep)

    def has_access(self, path, access_list):
        path = self.strip_path(path)
        user = self.cmd_channel.username

        if isinstance(access_list, Access):
            access_list = [access_list]
        for access in access_list:
            try:
                if has_access(user, path, access):
                    log(__name__).info("%s granted to %s for '%s'",
                                       access, user, path)
                    return True
                log(__name__).debug("%s not allowed for %s at '%s'",
                                    access, user, path)
            except AccessError:
                pass
        log(__name__).warning("%s not allowed for %s at '%s'",
                              access_list, user, path)
        return False

    def get_user_by_uid(self, uid):
        return "fus"

    def get_group_by_gid(self, gid):
        return "fus"

    def chdir(self, path):
        if self.has_access(path, [Access.LIST, Access.MKDIR, Access.UPLOAD]):
            return AbstractedFS.chdir(self, path)
        else:
            raise FilesystemError("invalid path")

    def mkdir(self, path):
        if self.has_access(path, Access.MKDIR):
            return AbstractedFS.mkdir(self, path)
        else:
            raise FilesystemError("invalid path")

    def listdir(self, path):
        user = self.cmd_channel.username
        if self.has_access(path, Access.LIST):
            dirs, files = list_dir(path)
            basepath = self.strip_path(path)
            filter_file_list(user, basepath, dirs, files)
            return dirs + files
        else:
            raise FilesystemError("invalid path")

    def remove(self, path):
        if self.has_access(path, Access.DELETE):
            return AbstractedFS.remove(self, path)
        else:
            raise FilesystemError("invalid path")

    def rename(self, src, dst):
        raise FilesystemError("invalid path")

    def chmod(self, path, mode):
        raise FilesystemError("invalid path")

    def open(self, filename, mode):
        path, name = os.path.split(filename)
        name = text.get_valid_filename(name)

        if "w" in mode:
            if self.has_access(path, Access.UPLOAD):
                return AbstractedFS.open(self, filename, mode)
            else:
                raise FilesystemError("invalid path")
        else:
            if self.has_access(path, Access.FETCH):
                return AbstractedFS.open(self, filename, mode)
            else:
                raise FilesystemError("invalid path")

    def mkstemp(self, suffix='', prefix='', path=None, mode='wb'):
        raise FilesystemError("invalid path")


def make_ftp_server(config):

    class DummyFtpServer:
        """Just a mock to make the FTP code happy when
        there is no server available"""

        def serve_forever(self, *args, **kwargs):
            pass

        def close_all(self, *args, **kwargs):
            pass

    try:
        ftp_handler = FTPHandler
        ftp_handler.authorizer = MyAuthorizer()
        ftp_handler.abstracted_fs = MyFilesystem

        ftp_handler.banner = "fus at your service."
        address = (config.get("global", "host"),
                   config.getint("global", "ftp_port"))
        ftp_server = FTPServer(address, ftp_handler)
        ftp_server.set_reuse_addr()

        return ftp_server
    except NoOptionError:
        log(__name__).warning("Not running FTP server, is 'ftp_port' configured?")
        log(__name__).debug("Error", exc_info=True)
    except Exception:
        log(__name__).warning("Not running FTP server, is pyftpdlib available?")
        log(__name__).debug("Error", exc_info=True)

    return DummyFtpServer()


config = load_config()
setup_logging(config)

ftp_server = make_ftp_server(config)

ftp_thread = threading.Thread(target=ftp_server.serve_forever, args=(1,))
ftp_thread.start()

loop = asyncio.get_event_loop()

try:
    web_if = WebIF(loop, config)
    try:
        log(__name__).info("Server running, CTRL-C to exit")
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    web_if.close()
except NoOptionError as e:
    log(__name__).error("Failed to start web interface: %s", e)

log(__name__).info("HTTP Server stopped")
ftp_server.close_all()
ftp_thread.join()
log(__name__).info("FTP Server stopped")
