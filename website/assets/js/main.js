/* RedForge Website — Main JS */

// ── Tab switcher ─────────────────────────────────────────
function initTabs() {
  document.querySelectorAll('.tabs').forEach(tabGroup => {
    tabGroup.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.dataset.tab;
        const parent = btn.closest('.tab-container') || document;
        tabGroup.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        parent.querySelectorAll('.tab-pane').forEach(p => {
          p.classList.toggle('active', p.id === target);
        });
      });
    });
  });
}

// ── Copy code ─────────────────────────────────────────────
function initCopyButtons() {
  document.querySelectorAll('.code-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const block = btn.closest('.code-block');
      const code = block ? block.querySelector('code') : null;
      if (code) {
        navigator.clipboard.writeText(code.textContent).then(() => {
          btn.textContent = 'Copied!';
          setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
        });
      }
    });
  });
}

// ── Sidebar active link ───────────────────────────────────
function initSidebarActive() {
  const current = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.sidebar-nav a').forEach(a => {
    const href = a.getAttribute('href') || '';
    if (href.includes(current) || (current === '' && href === 'index.html')) {
      a.classList.add('active');
    }
  });
}

// ── Probe search filter ───────────────────────────────────
function initProbeSearch() {
  const searchInput = document.getElementById('probe-search');
  if (!searchInput) return;
  const cards = document.querySelectorAll('.probe-card');
  searchInput.addEventListener('input', () => {
    const query = searchInput.value.toLowerCase();
    cards.forEach(card => {
      const text = card.textContent.toLowerCase();
      card.style.display = text.includes(query) ? '' : 'none';
    });
  });
}

// ── Smooth scroll for anchor links ───────────────────────
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const target = document.querySelector(a.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });
}

// ── Navbar scroll effect ──────────────────────────────────
function initNavbar() {
  const navbar = document.querySelector('.navbar');
  if (!navbar) return;
  window.addEventListener('scroll', () => {
    navbar.style.boxShadow = window.scrollY > 10
      ? '0 4px 24px rgba(0,0,0,0.4)'
      : 'none';
  });
}

// ── Mobile sidebar toggle ─────────────────────────────────
function initMobileSidebar() {
  const toggle = document.getElementById('sidebar-toggle');
  const sidebar = document.querySelector('.docs-sidebar');
  if (!toggle || !sidebar) return;
  toggle.addEventListener('click', () => {
    sidebar.style.display = sidebar.style.display === 'block' ? '' : 'block';
  });
}

// ── Collapsible API endpoints ─────────────────────────────
function initApiEndpoints() {
  document.querySelectorAll('.api-endpoint-header').forEach(header => {
    const body = header.nextElementSibling;
    if (body && body.classList.contains('api-endpoint-body')) {
      header.addEventListener('click', () => {
        const isOpen = body.style.display !== 'none';
        body.style.display = isOpen ? 'none' : 'block';
        const arrow = header.querySelector('.api-arrow');
        if (arrow) arrow.textContent = isOpen ? '›' : '⌄';
      });
    }
  });
}

// ── Animate hero stats ────────────────────────────────────
function animateStats() {
  const stats = document.querySelectorAll('.stat-value[data-count]');
  stats.forEach(el => {
    const target = parseInt(el.dataset.count);
    const suffix = el.dataset.suffix || '';
    let current = 0;
    const step = Math.ceil(target / 40);
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = current + suffix;
      if (current >= target) clearInterval(timer);
    }, 30);
  });
}

// ── Init ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initCopyButtons();
  initSidebarActive();
  initProbeSearch();
  initSmoothScroll();
  initNavbar();
  initMobileSidebar();
  initApiEndpoints();
  animateStats();
});
