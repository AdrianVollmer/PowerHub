from django.shortcuts import render, redirect
from django import forms
from django.http import HttpResponse


from powerhub.clipboard import clipboard
from powerhub.stager import modules, stager_str, callback_url
from powerhub.upload import save_file
#  from powerhub.av_evasion import clean_ps1

from datetime import datetime
from base64 import b64decode


class UploadFileForm(forms.Form):
    file = forms.FileField()


def index(request):
    pl_size = len(payload(request).content)
    active_modules = sum(1 for m in modules if m.active)
    context = {
        "dl_str": stager_str,
        "pl_size": "%d bytes" % pl_size,
        "active_modules": active_modules,
        "clipboard": clipboard,
        "modules": modules,
        "upload_form": UploadFileForm(),
    }
    return render(request, "hub/index.html", context)


def add_clipboard(request):
    content = request.POST["content"]
    clipboard.add(
        content,
        datetime.utcnow(),
        request.META.get('REMOTE_ADDR'),
    )
    return redirect('/')


def del_clipboard(request):
    n = int(request.POST["n"]) - 1
    clipboard.delete(n)
    return redirect('/')


def activate_module(request):
    n = int(request.POST["n"]) - 1
    if n == -2:
        for m in modules:
            m.activate()
    else:
        modules[n].activate()
    return redirect('/')


def deactivate_module(request):
    n = int(request.POST["n"]) - 1
    if n == -2:
        for m in modules:
            m.deactivate()
    else:
        modules[n].deactivate()
    return redirect('/')


def payload(request):
    context = {
        "modules": modules,
        "callback_url": callback_url,
    }
    if 'm' in request.GET:
        n = int(request.GET['m'])
        if n < len(modules):
            modules[n].activate()
            result = HttpResponse(
                modules[n].code,
                content_type='text/plain; charset=utf-8'
            )
        else:
            result = HttpResponse("not found")
    else:
        result = render(request,
                        "hub/payload.ps1",
                        context,
                        content_type='text/plain'
                        )
    return result


def upload(request):
    file = request.FILES["file"]
    save_file(file)
    return redirect('/')


def debug(request):
    m = request.GET['m']
    result = [x for x in modules if m in x.name]
    if result:
        response = HttpResponse(
            b64decode(result[0].code),
            content_type='text/plain; charset=utf-8'
        )
    else:
        response = HttpResponse("not found")
    return response
