function toggleDiv(id) {
    var div = document.getElementById(id);
    div.style.display = div.style.display == "none" ? "block" : "none";
}

function deleteClip(n) {
     $.post("clipboard/delete", {n: n});
     $("#card-" + n.toString()).remove();
}

$('#myTab a').click(function(e) {
  e.preventDefault();
  $(this).tab('show');
});

// store the currently selected tab in the hash value
$("ul.nav-tabs > li > a").on("shown.bs.tab", function(e) {
  var id = $(e.target).attr("href").substr(1);
  window.location.hash = id;
});

// on load of the page: switch to the currently selected tab
$(document).ready(function() {
    var hash = window.location.hash;
    $('#myTab a[href="' + hash + '"]').tab('show');
});

$(document).ready(function(){
    $('[data-toggle="popover"]').popover();
});

