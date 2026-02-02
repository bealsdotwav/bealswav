// home.js

// Helper: run now if DOM already ready
function onReady(fn){
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
  else fn();
}

/* ─────────────────────────────────────────────────────────────
   INTRO (every load, fixed duration)
───────────────────────────────────────────────────────────── */
onReady(function(){
  const intro = document.getElementById('intro');
  if (!intro) return;

  requestAnimationFrame(() => intro.classList.add('play'));
  setTimeout(() => { if (intro) intro.remove(); }, 2950);
});

/* ─────────────────────────────────────────────────────────────
   MOBILE DRAWER
───────────────────────────────────────────────────────────── */
onReady(function(){
  const btn = document.getElementById('menuBtn');
  const drawer = document.getElementById('drawer');
  if (!btn || !drawer) return;

  btn.addEventListener('click', () => {
    drawer.style.display = (drawer.style.display === 'block') ? 'none' : 'block';
  });

  drawer.addEventListener('click', (e) => {
    if (e.target && e.target.tagName === 'A') drawer.style.display = 'none';
  });

  window.addEventListener('resize', () => {
    if (window.innerWidth > 760) drawer.style.display = 'none';
  });
});

/* ─────────────────────────────────────────────────────────────
   LOGIN/ACCOUNT LABELS
───────────────────────────────────────────────────────────── */
onReady(function(){
  function sync(){
    const isLoggedIn = localStorage.getItem('loggedIn') === 'true';
    const loginTop = document.getElementById('loginTop');
    const loginMobile = document.getElementById('loginMobile');

    if (loginTop){
      loginTop.textContent = isLoggedIn ? 'Account' : 'Login';
      loginTop.href = isLoggedIn ? '/account.html' : '/login.html';
    }
    if (loginMobile){
      loginMobile.textContent = isLoggedIn ? 'Account' : 'Login';
      loginMobile.href = isLoggedIn ? '/account.html' : '/login.html';
    }
  }

  sync();
});

/* ─────────────────────────────────────────────────────────────
   CAROUSEL (dots/autoplay/swipe)
   IMPORTANT: index.html has an embed slide FIRST with data-noslide.
   We exclude it from dots, but it's still physically slide 0 in the track.
   So we translate by (idx + 1) to account for that offset.
───────────────────────────────────────────────────────────── */
onReady(function initCarousel(){
  const track    = document.getElementById('track');
  const dotsWrap = document.getElementById('dots');
  const chip     = document.getElementById('chip');
  const prevBtn  = document.getElementById('prev');
  const nextBtn  = document.getElementById('next');
  const viewport = document.getElementById('viewport');

  if (!track || !dotsWrap || !chip || !prevBtn || !nextBtn || !viewport) return;

  // Exclude the embed slide (it has data-noslide in your HTML)
  const slides = Array.from(track.querySelectorAll('.slide:not([data-noslide])'));
  if (!slides.length) return;

  let idx = 0;          // slides[0] is the first LINK slide (Music)
  let timer = null;

  // Build dots
  dotsWrap.innerHTML = '';
  slides.forEach((_, i) => {
    const dot = document.createElement('button');
    dot.className = 'dot';
    dot.type = 'button';
    dot.setAttribute('aria-label', `Go to slide ${i + 1}`);
    dot.addEventListener('click', () => setIndex(i, true));
    dotsWrap.appendChild(dot);
  });

  function setIndex(i, user=false){
    idx = (i + slides.length) % slides.length;

    // +1 offset because embed slide is still the first child in #track
    track.style.transform = `translateX(-${(idx + 1) * 100}%)`;

    chip.textContent = slides[idx].getAttribute('data-chip') || 'Featured';

    const dots = dotsWrap.querySelectorAll('.dot');
    dots.forEach((d, di) => d.setAttribute('aria-current', di === idx ? 'true' : 'false'));

    if (user) restart();
  }

  function start(){ timer = setInterval(() => setIndex(idx + 1), 5600); }
  function stop(){ if (timer) clearInterval(timer); timer = null; }
  function restart(){ stop(); start(); }

  prevBtn.addEventListener('click', () => setIndex(idx - 1, true));
  nextBtn.addEventListener('click', () => setIndex(idx + 1, true));

  viewport.addEventListener('mouseenter', stop);
  viewport.addEventListener('mouseleave', start);
  viewport.addEventListener('focusin', stop);
  viewport.addEventListener('focusout', start);

  // Swipe (do not steal taps from links/controls; ignore iframe)
  let down = false, startX = 0, dx = 0;

  function isInteractiveTarget(el){
    return !!(el && el.closest && el.closest('a, button, input, select, textarea, label'));
  }

  viewport.addEventListener('pointerdown', (e) => {
    if (e.target.closest && e.target.closest('iframe')) return;
    if (isInteractiveTarget(e.target)) return;

    down = true;
    startX = e.clientX;
    dx = 0;
    stop();
  });

  viewport.addEventListener('pointermove', (e) => {
    if (!down) return;
    dx = e.clientX - startX;
  });

  viewport.addEventListener('pointerup', () => {
    if (!down) return;
    down = false;

    if (Math.abs(dx) > 40) setIndex(idx + (dx < 0 ? 1 : -1), true);
    else restart();
  });

  viewport.addEventListener('pointercancel', () => { down = false; restart(); });

  // Start on Music (first link slide), not the embed
  setIndex(0);
  start();
});

/* ─────────────────────────────────────────────────────────────
   STUDIO SLIDESHOW
───────────────────────────────────────────────────────────── */
onReady(function(){
  const images = [
    "/assets/images/S1.jpeg","/assets/images/S2.jpeg","/assets/images/S3.jpeg",
    "/assets/images/S4.jpeg","/assets/images/S5.jpeg","/assets/images/S6.jpeg",
    "/assets/images/S7.jpeg","/assets/images/S8.jpeg","/assets/images/S9.jpeg",
    "/assets/images/S10.jpeg","/assets/images/S11.jpeg","/assets/images/S12.jpeg",
    "/assets/images/S13.jpeg","/assets/images/S14.jpeg","/assets/images/S15.jpeg",
    "/assets/images/S16.jpeg","/assets/images/S17.jpeg"
  ];

  const imgA = document.getElementById('imgA');
  const imgB = document.getElementById('imgB');
  if (!imgA || !imgB) return;

  let i = 0;
  let showingA = true;

  function preload(src){
    return new Promise((resolve) => {
      const im = new Image();
      im.onload = () => resolve(src);
      im.onerror = () => resolve(src);
      im.src = src;
    });
  }

  async function swap(){
    const nextSrc = images[i % images.length];
    i++;
    await preload(nextSrc);

    const show = showingA ? imgB : imgA;
    const hide = showingA ? imgA : imgB;

    show.src = nextSrc;

    requestAnimationFrame(() => {
      show.classList.add('show');
      hide.classList.remove('show');
      showingA = !showingA;
    });
  }

  imgA.src = images[0];
  imgA.classList.add('show');
  i = 1;

  setInterval(swap, 4200);
});

/* ─────────────────────────────────────────────────────────────
   VIDEO SEARCH / FILTER / SORT
───────────────────────────────────────────────────────────── */
onReady(function(){
  const grid = document.getElementById('videoGrid');
  const q = document.getElementById('q');
  const artist = document.getElementById('artist');
  const sort = document.getElementById('sort');
  const empty = document.getElementById('empty');
  if (!grid || !q || !artist || !sort || !empty) return;

  const cards = Array.from(grid.querySelectorAll('.vcard'));
  if (!cards.length) return;

  const names = new Set();
  cards.forEach(c => {
    const a = (c.getAttribute('data-artist') || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    a.forEach(x => names.add(x));
  });

  Array.from(names).sort((a,b)=>a.localeCompare(b)).forEach(n=>{
    const opt = document.createElement('option');
    opt.value = n;
    opt.textContent = n;
    artist.appendChild(opt);
  });

  function apply(){
    const term = (q.value || '').trim().toLowerCase();
    const who = (artist.value || '').trim();
    const mode = sort.value;

    let filtered = cards.filter(c => {
      const t = (c.getAttribute('data-title') || '').toLowerCase();
      const a = (c.getAttribute('data-artist') || '').toLowerCase();
      const okTerm = !term || t.includes(term) || a.includes(term);
      const okArtist = !who || (c.getAttribute('data-artist') || '')
        .split(',')
        .map(s=>s.trim())
        .includes(who);
      return okTerm && okArtist;
    });

    const byDate = (x) => (x.getAttribute('data-date') || '1900-01-01');

    if (mode === 'oldest') filtered.sort((a,b)=> byDate(a).localeCompare(byDate(b)));
    else if (mode === 'az') filtered.sort((a,b)=> (a.getAttribute('data-title')||'').localeCompare(b.getAttribute('data-title')||''));
    else if (mode === 'za') filtered.sort((a,b)=> (b.getAttribute('data-title')||'').localeCompare(a.getAttribute('data-title')||''));
    else filtered.sort((a,b)=> byDate(b).localeCompare(byDate(a)));

    grid.innerHTML = '';
    filtered.forEach(c => grid.appendChild(c));
    empty.style.display = filtered.length ? 'none' : 'block';
  }

  q.addEventListener('input', apply);
  artist.addEventListener('change', apply);
  sort.addEventListener('change', apply);

  apply();
});

/* ─────────────────────────────────────────────────────────────
   TICKER (duplicate + measure + animate exact px distance)
───────────────────────────────────────────────────────────── */
onReady(function(){
  const track = document.getElementById('tickerTrack');
  const item = document.getElementById('tickerItem');
  if (!track || !item) return;

  function rebuild(){
    while (track.children.length > 1) track.removeChild(track.lastChild);

    const viewportW = window.innerWidth || 1200;
    let totalW = item.getBoundingClientRect().width;

    while (totalW < viewportW * 2) {
      const clone = item.cloneNode(true);
      clone.removeAttribute('id');
      clone.setAttribute('aria-hidden', 'true');
      track.appendChild(clone);
      totalW += clone.getBoundingClientRect().width;
    }

    const baseW = item.getBoundingClientRect().width;
    const pxPerSec = 90;
    const dur = Math.max(16, Math.min(40, baseW / pxPerSec));

    const old = document.getElementById('tickerStyle');
    if (old) old.remove();

    const style = document.createElement('style');
    style.id = 'tickerStyle';
    style.textContent = `
      @keyframes tickerMovePx {
        0% { transform: translateX(0); }
        100% { transform: translateX(-${baseW}px); }
      }
      #tickerTrack { animation: tickerMovePx ${dur}s linear infinite; }
    `;
    document.head.appendChild(style);
  }

  window.addEventListener('load', rebuild);
  window.addEventListener('resize', () => { setTimeout(rebuild, 120); });
  rebuild();
});
