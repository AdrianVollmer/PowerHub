from base64 import urlsafe_b64decode
import binascii
from datetime import datetime
from functools import wraps
import logging
import os
import shutil
from tempfile import TemporaryDirectory

import flask.cli
from flask import Blueprint, render_template, request, Response, redirect, \
         send_from_directory, flash, abort, make_response

from powerhub.sql import get_clip_entry_list
from powerhub.stager import build_cradle
import powerhub.modules as phmod
from powerhub.upload import save_file, get_filelist
from powerhub.directories import directories
from powerhub.payloads import create_payload
from powerhub.tools import decrypt_aes
from powerhub.repos import repositories, install_repo
from powerhub.hiddenapp import hidden_app
from powerhub.dhkex import DH_ENDPOINT, dh_kex
from powerhub.parameters import param_collection


# Disable startup banner
flask.cli.show_server_banner = lambda *args: None

app = Blueprint('app', __name__)
log = logging.getLogger(__name__)

if log.getEffectiveLevel() <= logging.DEBUG:
    logging.getLogger("socketio").setLevel(logging.WARN)
    logging.getLogger("engineio").setLevel(logging.WARN)


def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    if app.args.AUTH:
        if ':' in app.args.AUTH:
            user, pwd = app.args.AUTH.split(':')[:2]
        else:
            user, pwd = app.args.AUTH, ''
        return username == user and password == pwd
    else:
        return True


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response('Could not verify your access level for that URL.\n'
                    'You have to login with proper credentials',
                    401,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*largs, **kwargs):
        auth = request.authorization
        if app.args.AUTH and (not auth or not check_auth(auth.username, auth.password)):
            return authenticate()
        return f(*largs, **kwargs)
    return decorated


def push_notification(msg):
    """Trigger a toast or an action on all windows

    :msg: A dict either with keys [title, subtitle, body, category] or
    [action, location]
    """
    app.socketio.emit(
        'push',
        msg,
        namespace="/push-notifications",
    )


@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory(os.path.join('static', 'css'), path)


@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory(os.path.join('static', 'js'), path)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['POST', 'GET'])
def catch_all(path):
    # Check if requests comes from a browser
    if not path:
        if 'text/html' in request.headers.get('Accept', ''):
            # Probably from Browser
            return redirect("/hub")
        else:
            # Probably from PowerShell
            return hidden_app.test_client().get('/')

    if path.startswith(DH_ENDPOINT):
        try:
            public_key = int(path.split('/')[1])
        except (IndexError, ValueError):
            abort(404)
        response = ' '.join(dh_kex(public_key, app.key))
        return Response(response, content_type='text/plain; charset=utf-8')

    # Return hidden endpoint
    try:
        # If path is of the form `<b64 string>/<n>`, then separate the `n`
        # That's the increment for incremental delivery
        if '/' in path:
            path, increment = path.split('/')[:2]
        else:
            increment = None
        path = urlsafe_b64decode(path)
        path = decrypt_aes(path, app.key).decode()
        if increment:
            path += '&increment=%s' % increment
        log.info("Forwarding hidden endpoint: %s" % path)
        return hidden_app.test_client().get('/'+path)
    except (binascii.Error, ValueError):
        abort(404)


# === Tab: Hub ==============================================


@app.route('/hub')
@requires_auth
def hub():
    clip_entries = [('-1', 'None')] + get_clip_entry_list(app.clipboard)
    param_collection.update_options('clip-exec', clip_entries)
    return render_template("html/hub.html", parameters=param_collection.parameters)


@app.route('/dlcradle')
@requires_auth
def dlcradle():
    """Return the download cradle as HTML fragment"""
    param_collection.parse_get_args(request.args)
    params = param_collection

    if params['launcher'] in [
        'powershell',
        'cmd',
        'cmd_enc',
        'bash',
    ]:
        cmd = build_cradle(params, app.key, app.callback_urls)
        href = None
    else:
        # Return a download button for payload
        import urllib
        href = urllib.parse.urlencode(request.args)
        href = '/dl?' + href
        cmd = None

    return render_template(
        "html/hub/download-cradle.html",
        dl_str=cmd,
        href=href,
    )


@app.route('/dl')
@requires_auth
def download_cradle():
    """Download payload as a file cradle"""
    try:
        param_collection.parse_get_args_short(request.args)
        filename, binary = create_payload(param_collection, app.key, app.callback_urls)
        response = make_response(binary)

        response.headers.set('Content-Type', 'application/octet-stream')
        response.headers.set(
            'Content-Disposition',
            'attachment',
            filename=filename,
        )
        return response
    except Exception as e:
        msg = {
            'title': 'An error occurred',
            'body': str(e),
            'category': 'danger',
        }
        flash(msg)
        log.exception(e)
        return redirect('/hub')


# === Tab: Modules ==============================================


@app.route('/modules')
@requires_auth
def modules():
    context = {
        "modules": phmod.modules,
        "repositories": list(repositories.keys()),
    }
    return render_template("html/modules.html", **context)


# === Tab: Clipboard ==============================================


@app.route('/clipboard')
@requires_auth
def clipboard():
    entries = list(app.clipboard.entries.values())
    context = {
        "clipboard": entries,
    }
    return render_template("html/clipboard.html", **context)


@app.route('/clipboard/add', methods=["POST"])
@requires_auth
def add_clipboard():
    """Add a clipboard entry"""
    content = request.form.get("content")
    app.clipboard.add(
        content,
        str(datetime.utcnow()).split('.')[0],
        request.remote_addr
    )
    push_notification({'action': 'reload', 'location': 'clipboard'})
    return redirect('/clipboard')


@app.route('/clipboard/delete', methods=["POST"])
@requires_auth
def del_clipboard():
    """Delete a clipboard entry"""
    id = int(request.form.get("id"))
    app.clipboard.delete(id)
    return ""


@app.route('/clipboard/executable', methods=["POST"])
@requires_auth
def executable_clipboard():
    """Set executable flag of a clipboard entry"""
    id = int(request.form.get("id"))
    value = (request.form.get("value") == 'true')
    app.clipboard.set_executable(id, value)
    return ""


@app.route('/clipboard/edit', methods=["POST"])
@requires_auth
def edit_clipboard():
    """Edit a clipboard entry"""
    id = int(request.form.get("id"))
    content = request.form.get("content")
    app.clipboard.edit(id, content)
    return ""


@app.route('/clipboard/del-all', methods=["POST"])
@requires_auth
def del_all_clipboard():
    """Delete all clipboard entries"""
    for id in list(app.clipboard.entries.keys()):
        app.clipboard.delete(id)
    return redirect("/clipboard")


@app.route('/clipboard/export', methods=["GET"])
@requires_auth
def export_clipboard():
    """Export all clipboard entries"""
    result = ""
    for e in list(app.clipboard.entries.values()):
        headline = "%s (%s)\r\n" % (e.time, e.IP)
        result += headline
        result += "="*(len(headline)-2) + "\r\n"
        result += e.content + "\r\n"*2
    return Response(result, content_type='text/plain; charset=utf-8')


# === Tab: File Exchange ==============================================


@app.route('/fileexchange')
@requires_auth
def fileexchange():
    context = {
        "files": get_filelist(),
    }
    return render_template("html/fileexchange.html", **context)


def process_file(file, is_from_script, remote_addr):
    """Save the file and return a message for push notification"""
    log.info("File received from %s: %s" % (remote_addr, file.filename))
    key = None
    if is_from_script:
        key = app.key
    save_file(file, key=key)
    msg = {}
    return msg


@app.route('/upload', methods=["POST"])
def upload():
    """Upload one or more files"""
    file_list = request.files.getlist("file[]")
    is_from_script = "script" in request.args
    remote_addr = request.remote_addr
    msg = {}
    for file in file_list:
        if file.filename == '':
            return redirect(request.url)
        if file:
            msg = process_file(file, is_from_script, remote_addr)
    push_notification({'action': 'reload', 'location': 'fileexchange'})
    if is_from_script:
        if msg:
            push_notification(msg)
        return ('OK', 200)
    else:
        return redirect('/fileexchange')


@app.route('/d/<path:filename>')
@requires_auth
def download_file(filename):
    """Download a file"""
    try:
        return send_from_directory(
            directories.UPLOAD_DIR,
            filename,
            as_attachment='dl' in request.args,
        )
    except PermissionError:
        abort(403)


@app.route('/d-all')
@requires_auth
def download_all():
    """Download archive of all uploaded files"""
    tmp_dir = TemporaryDirectory()
    file_name = "powerhub_upload_export_" + \
                datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    shutil.make_archive(os.path.join(tmp_dir.name, file_name),
                        "zip",
                        directories.UPLOAD_DIR)
    return send_from_directory(tmp_dir.name,
                               file_name + ".zip",
                               as_attachment=True)


# === Tab: Modules =================================================


@app.route('/getrepo', methods=["POST"])
@requires_auth
def get_repo():
    """Download a specified repository"""
    try:
        install_repo(
            request.form['repo'],
            request.form['custom-repo']
        )
        msg = {
            'title': "Success",
            'body': "%s has been installed" % request.form['repo'],
            'category': 'success',
        }
    except Exception as e:
        log.exception(e)
        msg = {
            'title': "Error",
            'body': str(e),
            'category': 'danger',
        }
    flash(msg, '')
    return redirect('/modules')


# === Tab: Static =================================================


@app.route('/list-static')
@requires_auth
def list_static():
    def get_dir(dir_name):
        directory = {
            'name': os.path.basename(dir_name),
            'files': [],
            'subdirs': [],
        }
        with os.scandir(dir_name) as it:
            for x in it:
                if x.is_file():
                    directory['files'].append(x.name)
                if x.is_dir():
                    subdir = get_dir(os.path.join(dir_name, x.name))
                    directory['subdirs'].append(subdir)
        directory['files'].sort()
        directory['subdirs'].sort(key=lambda x: x['name'])
        return directory
    context = {
        'rootdir': get_dir(directories.STATIC_DIR)
    }
    return render_template('html/list-static.html', **context)


@app.route('/static/<path:filename>')
def server_static(filename):
    try:
        return send_from_directory(directories.STATIC_DIR,
                                   filename,
                                   as_attachment=False)
    except PermissionError:
        abort(403)
