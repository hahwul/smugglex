let searchIndex = null;
let fuse = null;

function openSearch() {
  document.getElementById('searchOverlay').classList.add('active');
  document.getElementById('searchInput').focus();
  if (!searchIndex) loadSearchIndex();
}

function closeSearch() {
  document.getElementById('searchOverlay').classList.remove('active');
  document.getElementById('searchInput').value = '';
  document.getElementById('searchResults').innerHTML = '';
}

async function loadSearchIndex() {
  try {
    const res = await fetch('/search.json');
    searchIndex = await res.json();
    fuse = new Fuse(searchIndex, {
      keys: ['title', 'content'],
      threshold: 0.3,
      includeMatches: true,
    });
  } catch (e) {
    console.error('Failed to load search index:', e);
  }
}

document.addEventListener('keydown', function (e) {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    openSearch();
  }
  if (e.key === 'Escape') {
    closeSearch();
  }
});

document.addEventListener('DOMContentLoaded', function () {
  const input = document.getElementById('searchInput');
  if (input) {
    input.addEventListener('input', function () {
      if (!fuse) return;
      const query = this.value.trim();
      const results = document.getElementById('searchResults');
      if (!query) {
        results.innerHTML = '';
        return;
      }
      const matches = fuse.search(query).slice(0, 8);
      if (matches.length === 0) {
        results.innerHTML = '<div class="search-no-results">No results found</div>';
        return;
      }
      results.innerHTML = matches
        .map(
          (m) =>
            `<a class="search-result-item" href="${m.item.url}">
          <div class="search-result-title">${m.item.title}</div>
          <div class="search-result-snippet">${(m.item.content || '').substring(0, 120)}...</div>
        </a>`
        )
        .join('');
    });
  }
});
