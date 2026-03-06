document.addEventListener('DOMContentLoaded', function () {
  const main = document.querySelector('.docs-main');
  const tocNav = document.getElementById('tocNav');
  const tocAside = document.getElementById('docsToc');
  if (!main || !tocNav || !tocAside) return;

  const headings = main.querySelectorAll('h2[id], h3[id]');
  if (headings.length < 2) {
    tocAside.classList.add('hidden');
    return;
  }

  headings.forEach(function (h) {
    const a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = h.textContent;
    if (h.tagName === 'H3') a.classList.add('toc-h3');
    tocNav.appendChild(a);
  });

  var tocLinks = tocNav.querySelectorAll('a');
  var ticking = false;

  function updateActive() {
    var scrollY = window.scrollY + 80;
    var current = null;
    headings.forEach(function (h) {
      if (h.offsetTop <= scrollY) current = h.id;
    });
    tocLinks.forEach(function (link) {
      link.classList.toggle('active', link.getAttribute('href') === '#' + current);
    });
    ticking = false;
  }

  window.addEventListener('scroll', function () {
    if (!ticking) {
      requestAnimationFrame(updateActive);
      ticking = true;
    }
  });

  updateActive();
});
