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

$(function() {
$('[data-toggle="popover"]').popover(
     {
         html: true,
         sanitize: false,
         content: function () {
             var id = $(this).attr('data-shellid');
             var result = $('#popover-content-' + id + " table").html();
             return result;
         }
    }
);
});

$('#reloadbutton').click(function(){
    $.post({url: "reload", success: modules_loaded});
});

function modules_loaded(data){
    var msg = $('<div>').html(data);
    $('#ajaxmsg').append(msg);
};

$("#shell-log-modal").on("show.bs.modal", function(e) {
    var link = $(e.relatedTarget).attr("href");
    $(this).find(".modal-body").load(link);
    $(this).find(".modal-footer a").attr("href", link+"&content=raw");
});

$('.kill-shell').click(function(){
    var id = $(this).closest('.card').find('.shell-tooltip').attr('data-shellid');
    $.post({
        url: "kill-shell",
        data: {"shellid": id},
        success: function() { location.reload(); },
    });
});

feather.replace();
