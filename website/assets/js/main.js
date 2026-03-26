/* RedForge — main.js */

// ── Tab switcher ──────────────────────────────────────────────
document.querySelectorAll('.tabs-bar').forEach(bar => {
  bar.addEventListener('click', e => {
    const btn = e.target.closest('.tab-btn');
    if (!btn) return;
    const target = btn.dataset.tab;
    const container = bar.closest('.dark-section, .section, .docs-content, body');
    bar.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    (container || document).querySelectorAll('.tab-panel').forEach(p => {
      p.classList.toggle('active', p.id === target);
    });
  });
});

// ── Copy buttons ──────────────────────────────────────────────
document.addEventListener('click', e => {
  const btn = e.target.closest('.code-copy, .install-copy');
  if (!btn) return;
  const text = btn.dataset.copy ||
    btn.closest('.code-block')?.querySelector('pre code')?.textContent || '';
  navigator.clipboard.writeText(text.trim()).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = orig; }, 1800);
  });
});

// ── Counter animation (stats) ─────────────────────────────────
const counters = document.querySelectorAll('[data-target]');
const countObs = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    const el = entry.target;
    const target = +el.dataset.target;
    const dur = 900;
    const start = performance.now();
    const tick = now => {
      const p = Math.min((now - start) / dur, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(ease * target);
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
    countObs.unobserve(el);
  });
}, { threshold: 0.5 });
counters.forEach(c => countObs.observe(c));

// ── OWASP bar animation ───────────────────────────────────────
const barObs = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) entry.target.classList.add('bar-ready');
  });
}, { threshold: 0.3 });
document.querySelectorAll('.owasp-cell').forEach(c => barObs.observe(c));

// ── Scroll reveal ─────────────────────────────────────────────
const revealObs = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      revealObs.unobserve(entry.target);
    }
  });
}, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });
document.querySelectorAll('.reveal').forEach(el => revealObs.observe(el));

// ── Staggered child reveals ───────────────────────────────────
const staggerObs = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    entry.target.querySelectorAll('.feat-cell, .owasp-cell').forEach((child, i) => {
      child.style.transitionDelay = `${i * 0.04}s`;
      child.style.opacity = '0';
      child.style.transform = 'translateY(12px)';
      child.style.transition = 'opacity 0.45s ease, transform 0.45s ease';
      setTimeout(() => {
        child.style.opacity = '1';
        child.style.transform = 'translateY(0)';
      }, i * 40);
    });
    staggerObs.unobserve(entry.target);
  });
}, { threshold: 0.05 });
document.querySelectorAll('.feat-grid, .owasp-grid').forEach(g => staggerObs.observe(g));

// ── Sidebar active link (docs) ─────────────────────────────────
const currentPath = location.pathname.split('/').pop();
document.querySelectorAll('.sidebar-nav a').forEach(a => {
  if (a.getAttribute('href') === currentPath ||
      a.getAttribute('href')?.endsWith(currentPath)) {
    a.classList.add('active');
  }
});

// ── API endpoint accordion ────────────────────────────────────
document.querySelectorAll('.endpoint-header').forEach(header => {
  header.addEventListener('click', () => {
    header.closest('.endpoint-block').classList.toggle('open');
  });
});

// ── Probe search + filter (docs/probes.html) ──────────────────
const searchInput = document.querySelector('.probe-search-input');
const filterBtns  = document.querySelectorAll('.filter-btn');
const probeCards  = document.querySelectorAll('.probe-card');

function filterProbes() {
  const q = searchInput?.value.toLowerCase() || '';
  const activeFilter = document.querySelector('.filter-btn.active')?.dataset.filter || 'all';
  probeCards.forEach(card => {
    const text = card.textContent.toLowerCase();
    const matchQ = !q || text.includes(q);
    const matchF = activeFilter === 'all' || text.includes(activeFilter.toLowerCase());
    card.style.display = (matchQ && matchF) ? '' : 'none';
  });
}

searchInput?.addEventListener('input', filterProbes);
filterBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    filterBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filterProbes();
  });
});

// ── Navbar scroll shadow ──────────────────────────────────────
const navbar = document.querySelector('.navbar');
window.addEventListener('scroll', () => {
  navbar?.classList.toggle('scrolled', window.scrollY > 8);
}, { passive: true });
