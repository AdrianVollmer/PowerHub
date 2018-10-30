from flask import Flask, render_template, request, Response, redirect

from powerhub.clipboard import clipboard
from powerhub.stager import modules, stager_str, callback_url
from powerhub.upload import save_file
from powerhub.tools import encrypt, compress, key
#  from powerhub.av_evasion import clean_ps1

from datetime import datetime
from base64 import b64decode, b64encode


app = Flask(__name__)


@app.route('/')
def index():
    active_modules = sum(1 for m in modules if m.active)
    context = {
        "dl_str": stager_str,
        "active_modules": active_modules,
        "clipboard": clipboard,
        "modules": modules,
    }
    return render_template("index.html", **context)


@app.route('/clipboard/add', methods=["POST"])
def add_clipboard():
    content = request.form.get("content")
    clipboard.add(
        content,
        datetime.utcnow(),
        request.remote_addr
    )
    return redirect('/')


@app.route('/clipboard/delete', methods=["POST"])
def del_clipboard():
    n = int(request.form.get("n")) - 1
    clipboard.delete(n)
    return redirect('/')


@app.route('/module/activate', methods=["POST"])
def activate_module():
    n = int(request.form.get("n")) - 1
    if n == -2:
        for m in modules:
            m.activate()
    else:
        modules[n].activate()
    return redirect('/')


@app.route('/module/deactivate', methods=["POST"])
def deactivate_module():
    n = int(request.form.get("n")) - 1
    if n == -2:
        for m in modules:
            m.deactivate()
    else:
        modules[n].deactivate()
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
def upload():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file:
        save_file(file)
        return redirect('/')
    return redirect('/')


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
