/* Table of contents — builds from headings, highlights active via
   IntersectionObserver (no scroll listeners). */
document.addEventListener('DOMContentLoaded', function () {
  var main = document.querySelector('.docs-main');
  var tocNav = document.getElementById('tocNav');
  var tocAside = document.getElementById('docsToc');
  if (!main || !tocNav || !tocAside) return;

  var headings = main.querySelectorAll('h2[id], h3[id]');
  if (headings.length < 2) { tocAside.classList.add('hidden'); return; }

  headings.forEach(function (h) {
    var a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = h.textContent;
    if (h.tagName === 'H3') a.classList.add('toc-h3');
    tocNav.appendChild(a);
  });

  var links = tocNav.querySelectorAll('a');
  function setActive(id) {
    links.forEach(function (l) { l.classList.toggle('active', l.getAttribute('href') === '#' + id); });
  }

  if (!('IntersectionObserver' in window)) { setActive(headings[0].id); return; }

  var visible = {};
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting; });
    var current = null;
    headings.forEach(function (h) { if (!current && visible[h.id]) current = h.id; });
    if (!current) {
      headings.forEach(function (h) { if (h.getBoundingClientRect().top < 120) current = h.id; });
    }
    if (current) setActive(current);
  }, { rootMargin: '-70px 0px -70% 0px', threshold: 0 });

  headings.forEach(function (h) { io.observe(h); });
  setActive(headings[0].id);
});
