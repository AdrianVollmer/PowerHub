from flask import Flask, render_template, request, Response, redirect, \
         send_from_directory

from powerhub.clipboard import clipboard as cb
from powerhub.stager import modules, stager_str, callback_url
from powerhub.upload import save_file, get_filelist, upload_dir
from powerhub.tools import encrypt, compress, key
from powerhub.auth import requires_auth
#  from powerhub.av_evasion import clean_ps1

from datetime import datetime
from base64 import b64decode, b64encode


app = Flask(__name__)


@app.route('/')
@requires_auth
def index():
    return redirect('/hub')


@app.route('/hub')
@requires_auth
def hub():
    context = {
        "dl_str": stager_str,
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
    n = int(request.form.get("n")) - 1
    cb.delete(n)
    return redirect('/')


@app.route('/ps')
def payload():
    context = {
        "modules": modules,
        "callback_url": callback_url,
        "key": key,
    }
    if 'm' in request.args:
        n = int(request.args.get('m'))
        if n < len(modules):
            modules[n].activate()
            result = Response(
                b64encode(encrypt(compress(modules[n].code), key)),
                content_type='text/plain; charset=utf-8'
            )
        else:
            result = Response("not found")
    else:
        result = render_template(
                        "payload.ps1",
                        **context,
                        content_type='text/plain'
        )
    return result


@app.route('/u', methods=["POST"])
@requires_auth
def upload():
    if 'file' not in request.files:
        return redirect('/fileexchange')
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file:
        save_file(file)
        return redirect('/fileexchange')
    return redirect('/fileexchange')


@app.route('/d/<path:filename>')
@requires_auth
def download_file(filename):
    return send_from_directory(upload_dir,
                               filename,
                               as_attachment=True)


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
