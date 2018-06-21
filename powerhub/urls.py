from django.conf.urls import url
import powerhub.views

urlpatterns = [
    url(r'^ps$', powerhub.views.payload),
    url(r'^clipboard/add$', powerhub.views.add_clipboard),
    url(r'^clipboard/delete$', powerhub.views.del_clipboard),
    url(r'^module/activate$', powerhub.views.activate_module),
    url(r'^module/deactivate$', powerhub.views.deactivate_module),
    url(r'^debug/', powerhub.views.debug),
    url(r'^u$', powerhub.views.upload),
    url(r'^$', powerhub.views.index),
]
