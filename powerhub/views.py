from django.shortcuts import render, redirect
from django import forms


from powerhub.clipboard import clipboard
from powerhub.stager import modules, stager_str
from powerhub.upload import save_file

from datetime import datetime


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
        "modules": [m for m in modules if m.active],
    }
    return render(request,
                  "hub/payload.ps1",
                  context,
                  content_type='text/plain'
                  )


def upload(request):
    file = request.FILES["file"]
    save_file(file)
    return redirect('/')
