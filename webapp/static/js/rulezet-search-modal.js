/**
 * rulezet-search-modal.js — Rulezet search results, as a big searchable/
 * filterable table (mirrors the look of Rulezet's own Rules Explorer table),
 * instead of a short inline list. Needed once a CVE/ATT&CK lookup can return
 * hundreds of rules and the analyst has to actually find the right one.
 *
 * Usage (from a wizard's "Search Rulezet" button handler):
 *   zsazsaRulezetSearch(fetch(...).then(zsazsaReadJson), rulesTextareaEl, 'CVE-2021-44228')
 *
 * The modal opens immediately in a loading state, then renders the table (or
 * an error/empty state) once the promise settles. Clicking a row opens the
 * existing single-rule code modal (window.zsazsaShowRuleCode).
 */
(function () {
  function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function escRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // Escapes text for HTML, then wraps the search term in <mark> — used for the
  // visible columns so a hit is obvious in a long, paginated table.
  function highlight(text, term) {
    const escaped = esc(text);
    if (!term) return escaped;
    const re = new RegExp('(' + escRegex(esc(term)) + ')', 'ig');
    return escaped.replace(re, '<mark>$1</mark>');
  }

  const PAGE_SIZE = 25;

  let modalEl, bsModal, queryEl, bodyEl, searchInput, formatSelect, matchMenu, matchBtnLabel, bulkAddBtn, resetFiltersBtn;
  let currentRules = [];
  let currentTarget = null;
  let currentPage = 1;
  // Selected rows, kept across pages/filters/re-renders until added or the
  // search itself is reset — bulk-add works across as many pages as needed.
  let selectedRules = new Set();
  // 'cve' or 'attack' — which field of a rule ({cve_ids} / {matched_techniques})
  // drove this search, so the table shows and filters on the right one.
  let currentMatchType = 'cve';
  // value -> checked. Rebuilt fresh on every new search; OR-filter (a rule
  // shows if at least one of its own match values is checked).
  let matchCheckState = {};

  // Changing a filter changes what "selected" even refers to (rows picked
  // under the old filter may no longer be visible, or may not even match the
  // new one) — clear the selection rather than leave a stale, now meaningless
  // "Add N selected" behind. Paging through the SAME filter does not call
  // this, so a cross-page bulk selection still works.
  function onFilterChanged() {
    currentPage = 1;
    selectedRules.clear();
    updateBulkAddButton();
    renderTable();
  }

  // Builds the ONE shared modal element both this file and rulezet-code-modal.js
  // use — a single Bootstrap modal instance that never closes/reopens when
  // going from the results table into a rule's code and back. Switching views
  // is just toggling which header/body/footer blocks are visible, so there is
  // no hide()/show() transition (and no backdrop flicker) between them at all;
  // see zsazsaShowSearchView/zsazsaShowDetailView below.
  function ensureModal() {
    if (modalEl) return;
    modalEl = document.createElement('div');
    modalEl.className = 'modal fade';
    modalEl.id = 'zs-rulezet-modal';
    modalEl.tabIndex = -1;
    modalEl.innerHTML = `
      <div class="modal-dialog modal-xl zs-rs-dialog modal-dialog-scrollable">
        <div class="modal-content">
          <div class="modal-header">
            <!-- Plain inline flex on these two, not Bootstrap's .d-flex utility: that
                 class carries !important, which a later el.style.display = 'none'
                 (a non-important inline style) cannot override — the two headers
                 would then show at the same time regardless of the current view. -->
            <div id="zs-rs-header" class="flex-grow-1 min-w-0" style="display:flex;align-items:center;gap:.5rem;">
              <h5 class="modal-title d-flex align-items-center gap-2 mb-0">
                <img src="${SCRIPT_ROOT}/static/rulezet-icon.png" alt="" style="height:20px;">
                Rulezet search — <span id="zs-rs-query" class="text-muted fw-normal"></span>
              </h5>
            </div>
            <div id="zs-rc-header" class="flex-grow-1 min-w-0" style="display:none;align-items:center;gap:.5rem;">
              <button type="button" class="btn btn-sm btn-outline-secondary" id="zs-rc-back" style="display:none;" title="Back to search results">
                <i class="fas fa-arrow-left"></i>
              </button>
              <h5 class="modal-title d-flex align-items-center gap-2 mb-0">
                <span class="badge zs-rulezet-format-badge" id="zs-rc-badge"></span>
                <span id="zs-rc-title"></span>
              </h5>
            </div>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body p-0">
            <div id="zs-rs-view">
              <div class="zs-rs-toolbar d-flex gap-2 p-2 border-bottom">
                <div class="input-group input-group-sm" style="max-width:320px;">
                  <span class="input-group-text"><i class="fas fa-magnifying-glass"></i></span>
                  <input type="text" class="form-control" id="zs-rs-search" placeholder="Filter by title, author, source…">
                </div>
                <select class="form-select form-select-sm" id="zs-rs-format" style="max-width:160px;">
                  <option value="">All formats</option>
                </select>
                <div class="dropdown">
                  <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button"
                          id="zs-rs-match-btn" data-bs-toggle="dropdown" data-bs-auto-close="outside">
                    <span id="zs-rs-match-label">Matches</span>
                  </button>
                  <div class="dropdown-menu p-2" id="zs-rs-match-menu" style="max-height:280px;overflow-y:auto;min-width:220px;"></div>
                </div>
                <button type="button" class="btn btn-sm btn-outline-secondary" id="zs-rs-reset-filters" style="display:none;" title="Reset filters">
                  <i class="fas fa-arrow-rotate-left"></i>
                </button>
                <button type="button" class="btn btn-sm btn-primary" id="zs-rs-bulk-add" style="display:none;">
                  <i class="fas fa-plus me-1"></i>Add <span id="zs-rs-bulk-count">0</span> selected
                </button>
                <button type="button" class="btn btn-sm btn-outline-secondary" id="zs-rs-select-all-filtered" style="display:none;"></button>
                <span class="small text-muted align-self-center ms-auto" id="zs-rs-count"></span>
              </div>
              <div id="zs-rs-body"></div>
            </div>
            <div id="zs-rc-view" style="display:none;">
              <div class="p-3">
                <div class="content-card zs-rc-meta-card mb-3">
                  <div class="card-header"><i class="fas fa-circle-info me-2"></i>Rule details</div>
                  <div class="card-body zs-rc-meta-grid" id="zs-rc-meta"></div>
                </div>
                <div class="zs-rc-frame">
                  <pre class="zs-rc-pre mb-0"><code id="zs-rc-code" class="hljs"></code></pre>
                </div>
              </div>
            </div>
          </div>
          <div class="modal-footer" id="zs-rc-footer" style="display:none;">
            <a href="#" id="zs-rc-open" target="_blank" rel="noopener" class="btn btn-outline-secondary">
              <i class="fas fa-arrow-up-right-from-square me-1"></i>Open on Rulezet
            </a>
            <button type="button" id="zs-rc-add" class="btn btn-primary">
              <i class="fas fa-plus me-1"></i>Add to Detection rules
            </button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modalEl);
    bsModal = new bootstrap.Modal(modalEl);
    queryEl = modalEl.querySelector('#zs-rs-query');
    bodyEl = modalEl.querySelector('#zs-rs-body');
    searchInput = modalEl.querySelector('#zs-rs-search');
    formatSelect = modalEl.querySelector('#zs-rs-format');
    matchMenu = modalEl.querySelector('#zs-rs-match-menu');
    matchBtnLabel = modalEl.querySelector('#zs-rs-match-label');
    bulkAddBtn = modalEl.querySelector('#zs-rs-bulk-add');
    resetFiltersBtn = modalEl.querySelector('#zs-rs-reset-filters');

    searchInput.addEventListener('input', onFilterChanged);
    formatSelect.addEventListener('change', onFilterChanged);
    bulkAddBtn.addEventListener('click', bulkAddSelected);
    resetFiltersBtn.addEventListener('click', function () {
      searchInput.value = '';
      formatSelect.value = '';
      Object.keys(matchCheckState).forEach((v) => { matchCheckState[v] = true; });
      onFilterChanged();
      populateMatchOptions();
    });
  }

  function hasActiveFilters() {
    if (searchInput.value.trim() || formatSelect.value) return true;
    return Object.values(matchCheckState).some((checked) => !checked);
  }

  // Toggle between the two views living inside the one shared modal — no
  // hide()/show() of the modal itself, so no transition and no backdrop
  // flicker going from the results table into a rule's code, or back.
  // Exposed globally so rulezet-code-modal.js can switch back to search.
  window.zsazsaShowRulezetSearchView = function () {
    ensureModal();
    modalEl.querySelector('#zs-rs-header').style.display = 'flex';
    modalEl.querySelector('#zs-rc-header').style.display = 'none';
    modalEl.querySelector('#zs-rs-view').style.display = '';
    modalEl.querySelector('#zs-rc-view').style.display = 'none';
    modalEl.querySelector('#zs-rc-footer').style.display = 'none';
  };
  window.zsazsaShowRulezetDetailView = function () {
    ensureModal();
    modalEl.querySelector('#zs-rs-header').style.display = 'none';
    modalEl.querySelector('#zs-rc-header').style.display = 'flex';
    modalEl.querySelector('#zs-rs-view').style.display = 'none';
    modalEl.querySelector('#zs-rc-view').style.display = '';
    modalEl.querySelector('#zs-rc-footer').style.display = '';
    bootstrap.Modal.getOrCreateInstance(modalEl).show();
  };

  function updateBulkAddButton() {
    bulkAddBtn.style.display = selectedRules.size ? '' : 'none';
    modalEl.querySelector('#zs-rs-bulk-count').textContent = selectedRules.size;
  }

  // Offers the choice the checkbox alone can't: select everything on this
  // page (the checkbox), or every row the current search/filters match,
  // across every page. Shown only when there is more than one page and every
  // row on the current page is already selected — and swaps to "clear" once
  // the whole filtered set is selected, so the link's meaning always matches
  // what a click on it will do.
  function updateSelectAllFilteredLink(filtered, pageRows) {
    const link = modalEl.querySelector('#zs-rs-select-all-filtered');
    const allPageSelected = pageRows.length > 0 && pageRows.every((r) => selectedRules.has(r));
    const allFilteredSelected = filtered.length > 0 && filtered.every((r) => selectedRules.has(r));

    if (filtered.length <= pageRows.length || !allPageSelected) {
      link.style.display = 'none';
      link.onclick = null;
      return;
    }

    link.style.display = '';
    if (allFilteredSelected) {
      link.textContent = 'Clear selection';
      link.onclick = function () {
        filtered.forEach((r) => selectedRules.delete(r));
        updateBulkAddButton();
        renderTable();
      };
    } else {
      link.textContent = 'Select all ' + filtered.length + ' matching rules';
      link.onclick = function () {
        filtered.forEach((r) => selectedRules.add(r));
        updateBulkAddButton();
        renderTable();
      };
    }
  }

  function bulkAddSelected() {
    selectedRules.forEach((rule) => zsazsaAddRuleReference(rule, currentTarget));
    currentRules = currentRules.filter((r) => !selectedRules.has(r));
    selectedRules.clear();
    updateBulkAddButton();
    populateFormatOptions();
    populateMatchOptions();
    renderTable();
  }

  function matchesOf(rule) {
    return currentMatchType === 'attack' ? (rule.matched_techniques || []) : (rule.cve_ids || []);
  }

  function rowMatches(rule, term, format) {
    if (format && (rule.format || '').toLowerCase() !== format) return false;
    const values = matchesOf(rule);
    if (values.length && !values.some((v) => matchCheckState[v])) return false;
    if (!term) return true;
    const haystack = [rule.title, rule.author, rule.source, rule.format]
      .join(' ').toLowerCase();
    return haystack.includes(term);
  }

  // Page-window algorithm ported from Rulezet's own <pagination> component
  // (app/static/js/components/pagination/pagination.js): up to maxVisible
  // (7) page buttons, always showing the first/last page, with an ellipsis
  // filling the gap on whichever side(s) don't fit around the current page.
  function paginationPages(totalPages, current, maxVisible) {
    if (totalPages <= maxVisible) {
      return Array.from({ length: totalPages }, (_, i) => ({ page: i + 1 }));
    }
    const half = Math.floor((maxVisible - 2) / 2);
    const items = [];
    const showLeadingEllipsis = current > half + 2;
    const showTrailingEllipsis = current < totalPages - half - 1;

    items.push({ page: 1 });
    if (showLeadingEllipsis) items.push({ ellipsis: true, key: 'start' });

    const rangeStart = showLeadingEllipsis
      ? (showTrailingEllipsis ? current - half : totalPages - (maxVisible - 3))
      : 2;
    const rangeEnd = showTrailingEllipsis
      ? (showLeadingEllipsis ? current + half : maxVisible - 2)
      : totalPages - 1;

    for (let p = rangeStart; p <= rangeEnd; p++) {
      if (p > 1 && p < totalPages) items.push({ page: p });
    }

    if (showTrailingEllipsis) items.push({ ellipsis: true, key: 'end' });
    items.push({ page: totalPages });
    return items;
  }

  // Markup/classes match Rulezet's own <pagination> component 1:1
  // (pag-wrapper/pag-btn/pag-btn--active/pag-btn--disabled/pag-ellipsis),
  // styled in rulezet.css with this app's theme variables instead of
  // Rulezet's own --brand/--bg-surface tokens.
  function paginationHtml(totalPages) {
    if (totalPages <= 1) return '';
    const items = paginationPages(totalPages, currentPage, 7).map((item) => item.ellipsis
      ? '<span class="zs-pag-ellipsis">…</span>'
      : `<button type="button" class="zs-pag-btn zs-rs-page${item.page === currentPage ? ' zs-pag-btn--active' : ''}"
                  ${item.page === currentPage ? 'aria-current="page"' : ''} data-page="${item.page}">${item.page}</button>`
    ).join('');
    return `
      <nav class="zs-pag-wrapper" aria-label="Rulezet results pages">
        <button type="button" class="zs-pag-btn zs-rs-page${currentPage <= 1 ? ' zs-pag-btn--disabled' : ''}"
                ${currentPage <= 1 ? 'disabled' : ''} data-page="${currentPage - 1}" aria-label="Previous page">
          <i class="fas fa-chevron-left" style="font-size:.65rem;"></i>
        </button>
        ${items}
        <button type="button" class="zs-pag-btn zs-rs-page${currentPage >= totalPages ? ' zs-pag-btn--disabled' : ''}"
                ${currentPage >= totalPages ? 'disabled' : ''} data-page="${currentPage + 1}" aria-label="Next page">
          <i class="fas fa-chevron-right" style="font-size:.65rem;"></i>
        </button>
      </nav>`;
  }

  function renderTable() {
    const term = searchInput.value.trim().toLowerCase();
    const format = formatSelect.value;
    const filtered = currentRules.filter((r) => rowMatches(r, term, format));

    resetFiltersBtn.style.display = hasActiveFilters() ? '' : 'none';
    modalEl.querySelector('#zs-rs-count').textContent =
      filtered.length + ' / ' + currentRules.length + ' rule(s)';

    if (!filtered.length) {
      bodyEl.innerHTML = '<p class="text-muted text-center p-4 mb-0">No rule matches this filter.</p>';
      updateSelectAllFilteredLink([], []);
      return;
    }

    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    currentPage = Math.min(Math.max(1, currentPage), totalPages);
    const pageRows = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
    updateSelectAllFilteredLink(filtered, pageRows);

    const matchLabel = currentMatchType === 'attack' ? 'ATT&CK' : 'CVE';
    const allPageSelected = pageRows.length > 0 && pageRows.every((r) => selectedRules.has(r));
    const rowsHtml = pageRows.map((rule) => `
      <tr class="zs-rs-row" data-idx="${currentRules.indexOf(rule)}">
        <td><input type="checkbox" class="form-check-input zs-rs-select" ${selectedRules.has(rule) ? 'checked' : ''}></td>
        <td><span class="badge zs-rulezet-format-badge">${highlight(rule.format || '?', term)}</span></td>
        <td class="zs-rs-title">${highlight(rule.title || 'Untitled rule', term)}</td>
        <td class="text-muted small">${highlight(rule.author || '', term)}</td>
        <td class="text-muted small">${esc(rule.license || '')}</td>
        <td>${matchesOf(rule).map((v) => `<span class="badge zs-rs-match-badge me-1">${esc(v)}</span>`).join('') || ''}</td>
        <td class="text-muted small">${rule.quality_score != null ? esc(rule.quality_score) : ''}</td>
        <td class="text-muted small text-nowrap">${esc(rule.last_modif || '')}</td>
        <td class="text-end">
          <button type="button" class="btn btn-sm btn-outline-primary zs-rs-add" title="Add to Detection rules without opening the code view">
            <i class="fas fa-plus"></i>
          </button>
        </td>
      </tr>`).join('');

    bodyEl.innerHTML = `
      <div class="p-3 pt-2">
        <div class="table-responsive zs-rs-table-wrap">
          <table class="table table-hover table-sm mb-0 align-middle zs-rs-table">
            <thead class="table-light sticky-top">
              <tr>
                <th><input type="checkbox" class="form-check-input" id="zs-rs-select-all" title="Select all on this page" ${allPageSelected ? 'checked' : ''}></th>
                <th>Format</th><th>Title</th><th>Author</th><th>License</th>
                <th>${esc(matchLabel)}</th><th>Quality</th><th>Last modified</th><th></th>
              </tr>
            </thead>
            <tbody>${rowsHtml}</tbody>
          </table>
        </div>
        <div class="mt-3">${paginationHtml(totalPages)}</div>
      </div>`;

    bodyEl.querySelectorAll('.zs-rs-page').forEach((btn) => {
      btn.addEventListener('click', function () {
        const page = parseInt(btn.dataset.page, 10);
        if (!page || page < 1 || page > totalPages || page === currentPage) return;
        currentPage = page;
        renderTable();
      });
    });

    bodyEl.querySelectorAll('.zs-rs-row').forEach((tr) => {
      const rule = currentRules[parseInt(tr.dataset.idx, 10)];
      tr.addEventListener('click', function (ev) {
        if (ev.target.closest('.zs-rs-add') || ev.target.closest('.zs-rs-select')) return;
        zsazsaShowRuleCode(rule, currentTarget, function () { removeRule(rule); }, zsazsaShowRulezetSearchView);
      });
      tr.querySelector('.zs-rs-add').addEventListener('click', function (ev) {
        ev.stopPropagation();
        zsazsaAddRuleReference(rule, currentTarget);
        removeRule(rule);
      });
      tr.querySelector('.zs-rs-select').addEventListener('click', function (ev) { ev.stopPropagation(); });
      tr.querySelector('.zs-rs-select').addEventListener('change', function (ev) {
        if (ev.target.checked) selectedRules.add(rule);
        else selectedRules.delete(rule);
        updateBulkAddButton();
        const headerCb = modalEl.querySelector('#zs-rs-select-all');
        if (headerCb) headerCb.checked = pageRows.every((r) => selectedRules.has(r));
      });
    });

    const selectAllCb = modalEl.querySelector('#zs-rs-select-all');
    if (selectAllCb) {
      selectAllCb.addEventListener('change', function () {
        pageRows.forEach((r) => { if (selectAllCb.checked) selectedRules.add(r); else selectedRules.delete(r); });
        updateBulkAddButton();
        renderTable();
      });
    }
  }

  function removeRule(rule) {
    currentRules = currentRules.filter((r) => r !== rule);
    selectedRules.delete(rule);
    updateBulkAddButton();
    populateFormatOptions();
    populateMatchOptions();
    renderTable();
  }

  function populateFormatOptions() {
    const formats = Array.from(new Set(currentRules.map((r) => (r.format || '').toLowerCase()).filter(Boolean))).sort();
    const current = formatSelect.value;
    formatSelect.innerHTML = '<option value="">All formats</option>'
      + formats.map((f) => `<option value="${esc(f)}">${esc(f.toUpperCase())}</option>`).join('');
    if (formats.includes(current)) formatSelect.value = current;
  }

  // Rebuilt on every currentRules change (new search, or a rule removed after
  // being added) so the list only ever offers values actually present. A
  // value's checked state, once set by the analyst, is kept across rebuilds;
  // a brand-new value (only possible right after a fresh search, where the
  // whole map is reset first) defaults to checked.
  function populateMatchOptions() {
    const values = Array.from(new Set(currentRules.flatMap((r) => matchesOf(r)))).sort();
    values.forEach((v) => { if (!(v in matchCheckState)) matchCheckState[v] = true; });

    const total = values.length;
    const checkedCount = values.filter((v) => matchCheckState[v]).length;
    matchBtnLabel.textContent = (currentMatchType === 'attack' ? 'ATT&CK' : 'CVE')
      + (checkedCount < total ? ' (' + checkedCount + '/' + total + ')' : '');

    if (!values.length) {
      matchMenu.innerHTML = '<span class="dropdown-item-text text-muted small">No matches to filter on.</span>';
      return;
    }

    matchMenu.innerHTML = `
      <div class="d-flex justify-content-between mb-1 px-1">
        <button type="button" class="btn btn-link btn-sm p-0" id="zs-rs-match-all">Select all</button>
        <button type="button" class="btn btn-link btn-sm p-0" id="zs-rs-match-none">Clear</button>
      </div>
      ${values.map((v) => `
        <label class="dropdown-item d-flex align-items-center gap-2 py-1">
          <input type="checkbox" class="form-check-input mt-0 zs-rs-match-cb" value="${esc(v)}" ${matchCheckState[v] ? 'checked' : ''}>
          ${esc(v)}
        </label>`).join('')}`;

    matchMenu.querySelector('#zs-rs-match-all').addEventListener('click', function () {
      values.forEach((v) => { matchCheckState[v] = true; });
      onFilterChanged();
      populateMatchOptions();
    });
    matchMenu.querySelector('#zs-rs-match-none').addEventListener('click', function () {
      values.forEach((v) => { matchCheckState[v] = false; });
      onFilterChanged();
      populateMatchOptions();
    });
    matchMenu.querySelectorAll('.zs-rs-match-cb').forEach((cb) => {
      cb.addEventListener('change', function () {
        matchCheckState[cb.value] = cb.checked;
        onFilterChanged();
        populateMatchOptions();
      });
    });
  }

  // resultPromise resolves to {ok, rules, error} (the shape /api/rulezet-lookup
  // and /api/rulezet-attack-lookup already return). targetTextareaEl: textarea
  // an "Add" click appends "title — url" to. queryLabel: shown in the modal
  // title (e.g. the CVE ID or ATT&CK technique searched for). matchType:
  // 'cve' (default) or 'attack' — which field of a rule identifies why it
  // matched, shown as its own table column and filter.
  window.zsazsaRulezetSearch = function (resultPromise, targetTextareaEl, queryLabel, matchType) {
    ensureModal();
    currentTarget = targetTextareaEl;
    currentPage = 1;
    currentMatchType = matchType === 'attack' ? 'attack' : 'cve';
    matchCheckState = {};
    selectedRules.clear();
    updateBulkAddButton();
    queryEl.textContent = queryLabel || '';
    searchInput.value = '';
    formatSelect.innerHTML = '<option value="">All formats</option>';
    modalEl.querySelector('#zs-rs-count').textContent = '';
    bodyEl.innerHTML = `
      <div class="text-center text-muted p-5">
        <i class="fas fa-spinner fa-spin fa-lg mb-2"></i>
        <div>Searching Rulezet…</div>
      </div>`;
    zsazsaShowRulezetSearchView();
    bsModal.show();

    resultPromise.then(function (data) {
      if (!data || !data.ok) {
        bodyEl.innerHTML = `<p class="text-danger text-center p-4 mb-0">Rulezet lookup failed: ${esc((data && data.error) || 'unknown error')}</p>`;
        return;
      }
      currentRules = (data.rules || []).filter((r) => !zsazsaHasRuleReference(r, currentTarget));
      if (!currentRules.length) {
        bodyEl.innerHTML = '<p class="text-muted text-center p-4 mb-0">No matching rules found on Rulezet (or every match was already added).</p>';
        return;
      }
      populateFormatOptions();
      populateMatchOptions();
      renderTable();
    }).catch(function (err) {
      bodyEl.innerHTML = `<p class="text-danger text-center p-4 mb-0">Rulezet lookup did not complete: ${esc(zsazsaErrorText(err))}</p>`;
    });
  };
})();
