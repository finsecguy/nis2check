// Ask for confirmation on forms marked data-confirm, and prevent double submits.
document.addEventListener("submit", function (e) {
  var form = e.target;
  var msg = form.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) {
    e.preventDefault();
    return;
  }
  var btn = form.querySelector("button[type=submit]");
  if (btn) {
    setTimeout(function () { btn.disabled = true; }, 0);
  }
});

// A select marked data-autosubmit (the language menu) saves as soon as it changes.
document.addEventListener("change", function (e) {
  var el = e.target;
  if (el.matches && el.matches("select[data-autosubmit]") && el.form) {
    el.form.submit();
  }
});
