// enable popover help
$(function() { $('[data-toggle="popover"]').popover(); });

function update_cradle() {
    if (!$('#dlcradle').length) {
        return
    } else {
        var flavor = $('#dlcradle').attr('data-flavor');
    };
    var parameters = {"flavor": flavor};
    $('#cradle-options select').each(function(){
        parameters[this.id] = this.value;
    });
    $('#cradle-options input').each(function(){
        parameters[this.id] = $(this).is(':checked');
        $(this).parent().hide();
    });
    $('#cradle-options select').each(function(){
        $('#cradle-options .relevant-to-'+this.value).each(function(){
            $(this).show();
        });
    });
    $.get(
        "dlcradle",
        parameters
    ).done(function(data) { $('#dlcradle').text(data); });
};

$(window).on('load', update_cradle);

$('#cradle-options select, #cradle-options input').on('change', update_cradle);

function toggleDiv(id) {
    var div = document.getElementById(id);
    div.style.display = div.style.display == "none" ? "block" : "none";
}

$('.edit-clipboard').click(function(e){
    e.preventDefault();
    var id = $(this).attr('data-id');
    var textbox = $(document.createElement('textarea'));
    var pre = $('#card-'+id).find('pre');
    textbox.text(pre.html());
    textbox.attr('class', 'form-control');
    pre.replaceWith(textbox);
    $('#buttons-'+id).collapse('show');
});

$('.edit-ok').click(function(){
    var id = $(this).attr('data-id');
    var textbox = $('#card-'+id).find('textarea');
    $.post({
        url: "clipboard/edit",
        data: {"id": id, "content": textbox.val()},
        success: function() { location.reload(); },
    });
});

$('.edit-cancel').click(function(e){
    e.preventDefault();
    var id = $(this).attr('data-id');
    $('#buttons-'+id).collapse('hide');
    var pre= $(document.createElement('pre'));
    var textbox = $('#card-'+id).find('textarea');
    pre.html(textbox.text());
    textbox.replaceWith(pre);
});

$('.delete-clipboard').click(function(e){
    e.preventDefault();
    var id = $(this).attr('data-id');
    $.post("clipboard/delete", {id: id});
    $("#card-" + id).remove();
});

$('#reloadbutton').click(function(){
    $.post({
        url: "reload",
        success: function() { location.reload(); },
    });
});

var socket;
$(document).ready(function(){
    // start up the SocketIO connection to the server
    socket = io.connect('//' + document.domain + ':' + location.port + '/push-notifications');
    // this is a callback that triggers when the 'push' event is emitted by the server.
    socket.on('push', function(msg) {
        var toast = $('#toast-container div').eq(0).clone(true).appendTo('#toast-container');
        toast.find('.toast-title').text(msg.title);
        toast.find('.toast-subtitle').text(msg.subtitle);
        toast.find('.toast-body').text(msg.msg);
        $('#toast-container .toast').last().on('hidden.bs.toast', function () {
            // remove the toast from the dom tree after it faded out
            $(this).remove();
        });
        actOnPushMsg(msg);
        if (msg.title != "") {
            $('#toast-container .toast').last().toast('show');
        };
    });
});

function actOnPushMsg(msg) {
    if (msg.msg.startsWith("Update Clipboard")
            && window.location.pathname == "/clipboard") {
            location.reload();
    } else if (msg.msg.startsWith("Update Fileexchange")
            && window.location.pathname == "/fileexchange") {
            location.reload();
    };
};

feather.replace();
