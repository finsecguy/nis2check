// Show stored UTC timestamps in the browser's local time, and tell the
// server which zone a datetime-local field was typed in.
(function () {
  function pad(n) { return String(n).padStart(2, "0"); }

  function localValue(iso) {
    var date = new Date(iso);
    if (isNaN(date.getTime())) return "";
    return date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate())
      + "T" + pad(date.getHours()) + ":" + pad(date.getMinutes());
  }

  document.querySelectorAll("[data-utc]").forEach(function (el) {
    var iso = el.getAttribute("data-utc");
    if (el.tagName === "INPUT") {
      var value = localValue(iso);
      if (value) el.value = value;
      return;
    }
    var date = new Date(iso);
    if (isNaN(date.getTime())) return;
    el.textContent = date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  });

  var zone = "";
  try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) { zone = ""; }
  document.querySelectorAll("input[name=client_tz]").forEach(function (el) { el.value = zone; });
  document.querySelectorAll("input[name=time_is_utc]").forEach(function (el) { el.value = zone ? "0" : "1"; });
})();
