from base64 import urlsafe_b64decode
import binascii
from datetime import datetime
import logging
import os
import shutil
from tempfile import TemporaryDirectory

from flask import Blueprint, render_template, request, Response, redirect, \
         send_from_directory, flash, abort, make_response

from werkzeug.exceptions import BadRequestKeyError

from powerhub.env import powerhub_app as ph_app

from powerhub.sql import get_clip_entry_list
from powerhub.stager import build_cradle
import powerhub.modules as phmod
from powerhub.upload import save_file, get_filelist
from powerhub.directories import directories
from powerhub.payloads import create_payload
from powerhub.tools import decrypt_aes
from powerhub.auth import requires_auth
from powerhub.repos import repositories, install_repo
from powerhub.hiddenapp import hidden_app
from powerhub.dhkex import DH_ENDPOINT, dh_kex


app = Blueprint('app', __name__)
log = logging.getLogger(__name__)

if not ph_app.args.DEBUG:
    logging.getLogger("socketio").setLevel(logging.WARN)
    logging.getLogger("engineio").setLevel(logging.WARN)


def push_notification(msg):
    """Trigger a toast or an action on all windows

    :msg: A dict either with keys [title, subtitle, body, category] or
    [action, location]
    """
    ph_app.socketio.emit(
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
        response = ' '.join(dh_kex(public_key, ph_app.key))
        return Response(response, content_type='text/plain; charset=utf-8')

    # Return hidden endpoint
    try:
        path = urlsafe_b64decode(path)
        path = decrypt_aes(path, ph_app.key).decode()
        log.info("Forwarding hidden endpoint: %s" % path)
        return hidden_app.test_client().get(path)
    except (binascii.Error, ValueError):
        abort(404)


# === Tab: Hub ==============================================


@app.route('/hub')
@requires_auth
def hub():
    clip_entries = get_clip_entry_list(ph_app.clipboard)
    context = {
        "clip_entries": clip_entries,
    }
    return render_template("html/hub.html", **context)


@app.route('/dlcradle')
@requires_auth
def dlcradle():
    try:
        if request.args['Launcher'] in [
            'powershell',
            'cmd',
            'cmd_enc',
            'bash',
        ]:
            cmd = build_cradle(request.args, ph_app.key)
            return render_template(
                "html/hub/download-cradle.html",
                dl_str=cmd,
            )
        else:
            import urllib
            href = urllib.parse.urlencode(request.args)
            return render_template(
                "html/hub/download-cradle.html",
                dl_str=None,
                href='/dl?' + href,
            )

    except BadRequestKeyError as e:
        log.error("Unknown key, must be one of %s" %
                  str(list(request.args.keys())))
        return (str(e), 500)


@app.route('/dl')
@requires_auth
def download_cradle():
    """Download payload as a file cradle"""
    try:
        filename, binary = create_payload(request.args)
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
    entries = list(ph_app.clipboard.entries.values())
    context = {
        "nonpersistent": ph_app.db is None,
        "clipboard": entries,
    }
    return render_template("html/clipboard.html", **context)


@app.route('/clipboard/add', methods=["POST"])
@requires_auth
def add_clipboard():
    """Add a clipboard entry"""
    content = request.form.get("content")
    ph_app.clipboard.add(
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
    ph_app.clipboard.delete(id)
    return ""


@app.route('/clipboard/executable', methods=["POST"])
@requires_auth
def executable_clipboard():
    """Set executable flag of a clipboard entry"""
    id = int(request.form.get("id"))
    value = (request.form.get("value") == 'true')
    ph_app.clipboard.set_executable(id, value)
    return ""


@app.route('/clipboard/edit', methods=["POST"])
@requires_auth
def edit_clipboard():
    """Edit a clipboard entry"""
    id = int(request.form.get("id"))
    content = request.form.get("content")
    ph_app.clipboard.edit(id, content)
    return ""


@app.route('/clipboard/del-all', methods=["POST"])
@requires_auth
def del_all_clipboard():
    """Delete all clipboard entries"""
    for id in list(ph_app.clipboard.entries.keys()):
        ph_app.clipboard.delete(id)
    return redirect("/clipboard")


@app.route('/clipboard/export', methods=["GET"])
@requires_auth
def export_clipboard():
    """Export all clipboard entries"""
    result = ""
    for e in list(ph_app.clipboard.entries.values()):
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
    log.info("File received - %s" % file.filename)
    save_file(file, encrypted=is_from_script)
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
