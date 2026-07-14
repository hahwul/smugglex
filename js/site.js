/* smugglex — site interactions
   - scroll reveal (IntersectionObserver, no scroll listeners)
   - mobile nav toggle
   - copy buttons (install + docs code blocks)
   - active sidebar / nav link
   Reduced motion is honored in CSS (.reveal forced visible). */

(function () {
  "use strict";

  /* ---------- Reveal on scroll ---------- */
  function initReveal() {
    var els = document.querySelectorAll(".reveal");
    if (!els.length) return;
    if (!("IntersectionObserver" in window)) {
      els.forEach(function (el) { el.classList.add("in"); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    els.forEach(function (el) { io.observe(el); });
  }

  /* ---------- Mobile nav ---------- */
  window.toggleNav = function () { document.body.classList.toggle("nav-open"); };
  window.closeNav = function () { document.body.classList.remove("nav-open"); };

  /* ---------- Copy helpers ---------- */
  function flash(btn, label) {
    var original = btn.dataset._orig || btn.innerHTML;
    btn.dataset._orig = original;
    btn.classList.add("copied");
    btn.innerHTML = '<svg class="ico"><use href="#i-check"/></svg>' + (label || " copied");
    setTimeout(function () { btn.classList.remove("copied"); btn.innerHTML = original; }, 1600);
  }
  function writeClip(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve) {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch (e) {}
      document.body.removeChild(ta); resolve();
    });
  }
  window.copyClip = function (btn) {
    writeClip(btn.dataset.clip || "").then(function () { flash(btn, " copied"); });
  };

  /* ---------- Copy buttons on docs code blocks ---------- */
  function initCodeCopy() {
    var pres = document.querySelectorAll(".docs-main pre");
    pres.forEach(function (pre) {
      if (pre.querySelector(".copy-code")) return;
      var code = pre.querySelector("code") || pre;
      var btn = document.createElement("button");
      btn.className = "copy-code";
      btn.type = "button";
      btn.setAttribute("aria-label", "Copy code");
      btn.innerHTML = '<svg class="ico"><use href="#i-copy"/></svg>';
      btn.addEventListener("click", function () {
        writeClip(code.innerText.replace(/\n$/, "")).then(function () { flash(btn, ""); });
      });
      pre.appendChild(btn);
    });
  }

  /* ---------- Active nav / sidebar link ---------- */
  function samePath(a, b) {
    var norm = function (p) { return p.replace(/\/index\.html$/, "/").replace(/\/$/, "") || "/"; };
    return norm(a) === norm(b);
  }
  function initActive() {
    var here = location.pathname;
    document.querySelectorAll(".sb-links a, .nav-links a").forEach(function (a) {
      var p;
      try { p = new URL(a.href).pathname; } catch (e) { return; }
      if (samePath(p, here)) a.classList.add("active");
    });
  }

  /* ---------- Wiring ---------- */
  function ready() {
    initReveal();
    initCodeCopy();
    initActive();
    document.querySelectorAll(".nav-links a").forEach(function (a) {
      a.addEventListener("click", window.closeNav);
    });
    window.addEventListener("resize", function () {
      if (window.innerWidth > 820) window.closeNav();
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ready);
  else ready();
})();
