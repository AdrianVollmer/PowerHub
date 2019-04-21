$('.dlcradle-options').change(function() {
    $.get(
        "dlcradle",
        {
            "proxy": $("#need-proxy").is(':checked'),
            "tlsv12": $("#need-tlsv12").is(':checked'),
        }
    ).done(function(data) { $('#dlcradle').text(data); });
});

function toggleDiv(id) {
    var div = document.getElementById(id);
    div.style.display = div.style.display == "none" ? "block" : "none";
}

function deleteClip(n) {
     $.post("clipboard/delete", {n: n});
     $("#card-" + n.toString()).remove();
}

$(document).ready(function(){
    $('[data-toggle="popover"]').popover();
});


$('#reloadbutton').click(function(){
    $.post({url: "reload", success: modules_loaded});
});

function modules_loaded(data){
    var msg = $('<div>').html(data);
    $('#ajaxmsg').append(msg);
};

$('[data-toggle=popover]').popover({
   content: $('#popover-content').html(),
   html: true
}).hover(function() {
   $(this).popover('show');
});

feather.replace();
