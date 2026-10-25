// name, why it matters, points
var CHECKS = [
  ["content-security-policy", "Prevents cross-site scripting (XSS)", 25],
  ["strict-transport-security", "Forces HTTPS (HSTS)", 25],
  ["x-frame-options", "Prevents clickjacking", 15],
  ["x-content-type-options", "Stops MIME-type sniffing", 15],
  ["referrer-policy", "Limits referrer leakage", 10],
  ["permissions-policy", "Restricts browser features", 10]
];

function parseHeaders(text) {
  var out = {};
  text.split("\n").forEach(function (line) {
    var i = line.indexOf(":");
    if (i > 0) {
      out[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
    }
  });
  return out;
}

function analyze(headersObj) {
  document.getElementById("error").textContent = "";
  var h = headersObj || parseHeaders(document.getElementById("headers").value);
  if (Object.keys(h).length === 0) {
    document.getElementById("error").textContent = "Please paste some headers first.";
    return;
  }

  var total = 0, earned = 0, rows = "";

  CHECKS.forEach(function (c) {
    total += c[2];
    if (h[c[0]]) {
      earned += c[2];
      rows += row("pass", "PASS", c[0], "Present: " + escapeHtml(h[c[0]].slice(0, 90)));
    } else {
      rows += row("fail", "FAIL", c[0], "Missing. " + c[1]);
    }
  });

  // CORS check (shown as information, not scored)
  var acao = h["access-control-allow-origin"];
  if (!acao) {
    rows += row("pass", "PASS", "CORS", "No Access-Control-Allow-Origin header (cross-origin reads not allowed)");
  } else if (acao === "*") {
    rows += row("warn", "WARN", "CORS", "Wildcard (*) lets any website read responses");
  } else {
    rows += row("pass", "PASS", "CORS", "Restricted to: " + escapeHtml(acao));
  }

  var score = Math.round(earned / total * 100);
  var grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  var color = score >= 75 ? "#2e9d4f" : score >= 40 ? "#e0a100" : "#d63b3b";

  document.getElementById("result").innerHTML =
    '<div class="score"><div class="num" style="color:' + color + '">' + score + '/100</div>' +
    '<div class="grade">Grade: ' + grade + '</div></div>' + rows;
}

function row(cls, status, name, detail) {
  return '<div class="row ' + cls + '"><b>' + status + '</b> ' + name + '<small>' + detail + '</small></div>';
}

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function fetchUrl() {
  var url = document.getElementById("url").value.trim();
  var err = document.getElementById("error");
  err.textContent = "";
  if (!url) { err.textContent = "Enter a URL first."; return; }
  if (!/^https?:\/\//i.test(url)) { url = "https://" + url; }

  fetch(url)
    .then(function (res) {
      var h = {};
      res.headers.forEach(function (value, name) { h[name.toLowerCase()] = value; });
      analyze(h);
    })
    .catch(function () {
      err.textContent = "Could not read headers. The site likely blocks cross-origin access (CORS). Use Option 1 and paste the headers instead.";
    });
}

function loadSample() {
  document.getElementById("headers").value =
    "content-security-policy: default-src 'self'\n" +
    "strict-transport-security: max-age=31536000; includeSubDomains\n" +
    "x-content-type-options: nosniff\n" +
    "access-control-allow-origin: *";
  analyze();
}