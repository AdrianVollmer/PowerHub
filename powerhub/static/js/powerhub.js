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

