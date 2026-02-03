// home.js

// Helper: run now if DOM already ready
function onReady(fn) {
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
  else fn();
}

/* ─────────────────────────────────────────────────────────────
   INTRO (every load, fixed duration)
───────────────────────────────────────────────────────────── */
onReady(function () {
  const intro = document.getElementById("intro");
  if (!intro) return;

  requestAnimationFrame(() => intro.classList.add("play"));
  setTimeout(() => {
    if (intro) intro.remove();
  }, 2950);
});

/* ─────────────────────────────────────────────────────────────
   MOBILE DRAWER
───────────────────────────────────────────────────────────── */
onReady(function () {
  const btn = document.getElementById("menuBtn");
  const drawer = document.getElementById("drawer");
  if (!btn || !drawer) return;

  btn.addEventListener("click", () => {
    drawer.style.display = drawer.style.display === "block" ? "none" : "block";
  });

  drawer.addEventListener("click", (e) => {
    if (e.target && e.target.tagName === "A") drawer.style.display = "none";
  });

  window.addEventListener("resize", () => {
    if (window.innerWidth > 760) drawer.style.display = "none";
  });
});

/* ─────────────────────────────────────────────────────────────
   LOGIN/ACCOUNT LABELS
───────────────────────────────────────────────────────────── */
onReady(function () {
  function sync() {
    const isLoggedIn = localStorage.getItem("loggedIn") === "true";
    const loginTop = document.getElementById("loginTop");
    const loginMobile = document.getElementById("loginMobile");

    if (loginTop) {
      loginTop.textContent = isLoggedIn ? "Account" : "Login";
      loginTop.href = isLoggedIn ? "/account.html" : "/login.html";
    }
    if (loginMobile) {
      loginMobile.textContent = isLoggedIn ? "Account" : "Login";
      loginMobile.href = isLoggedIn ? "/account.html" : "/login.html";
    }
  }

  sync();
});

/* ─────────────────────────────────────────────────────────────
   CAROUSEL (DOTS/AUTOPLAY/SWIPE) - DESKTOP FIX THAT ACTUALLY WORKS
   Switches from translateX to native horizontal scrolling.
   Why: desktop browsers + mixed <div>/<a> flex children can be "fine" on mobile
   and mysteriously refuse to move on desktop because humans love chaos.
───────────────────────────────────────────────────────────── */
onReady(function initCarousel() {
  const track = document.getElementById("track");
  const dotsWrap = document.getElementById("dots");
  const chip = document.getElementById("chip");
  const prevBtn = document.getElementById("prev");
  const nextBtn = document.getElementById("next");
  const viewport = document.getElementById("viewport");

  if (!track || !dotsWrap || !chip || !prevBtn || !nextBtn || !viewport) return;

  // The first physical slide is an embed <div class="slide" data-noslide="1">.
  // We want dots/autoplay to control only the link slides after it.
  const slides = Array.from(track.querySelectorAll(".slide:not([data-noslide])"));
  if (!slides.length) return;

  // Make viewport scroll-based even if CSS says overflow:hidden.
  // This is the "stop relying on fragile transforms" fix.
  viewport.style.overflowX = "auto";
  viewport.style.overflowY = "hidden";
  viewport.style.scrollBehavior = "smooth";
  viewport.style.webkitOverflowScrolling = "touch";
  viewport.style.scrollSnapType = "x mandatory";
  viewport.style.scrollbarWidth = "none"; // firefox hide
  viewport.style.msOverflowStyle = "none"; // old edge
  viewport.classList.add("js-carousel-scroll");
  // Hide scrollbar webkit
  if (!document.getElementById("carouselScrollStyle")) {
    const s = document.createElement("style");
    s.id = "carouselScrollStyle";
    s.textContent = `
      #viewport.js-carousel-scroll::-webkit-scrollbar { display:none; }
      #track { transform:none !important; }
      #track > .slide, #track > a.slide { scroll-snap-align:start; }
    `;
    document.head.appendChild(s);
  }

  let idx = 0; // idx is within "slides" (link slides only)
  let timer = null;
  let isBooted = false;
  let isProgrammaticScroll = false;

  function slideWidth() {
    return viewport.getBoundingClientRect().width || 0;
  }

  function setChipAndDots() {
    chip.textContent = slides[idx].getAttribute("data-chip") || "Featured";
    const dots = dotsWrap.querySelectorAll(".dot");
    dots.forEach((d, di) => d.setAttribute("aria-current", di === idx ? "true" : "false"));
  }

  function goToIndex(i, user = false) {
    idx = (i + slides.length) % slides.length;
    setChipAndDots();

    const w = slideWidth();
    if (w < 10) return;

    // +1 because the embed slide is physically first in the track.
    const left = (idx + 1) * w;

    isProgrammaticScroll = true;
    viewport.scrollTo({ left, behavior: user ? "smooth" : "auto" });
    // Release programmatic flag after scroll settles a bit
    setTimeout(() => {
      isProgrammaticScroll = false;
    }, 180);

    if (user) restart();
  }

  function start() {
    stop();
    timer = setInterval(() => goToIndex(idx + 1, false), 5600);
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  function restart() {
    stop();
    start();
  }

  // Dots
  dotsWrap.innerHTML = "";
  slides.forEach((_, i) => {
    const dot = document.createElement("button");
    dot.className = "dot";
    dot.type = "button";
    dot.setAttribute("aria-label", `Go to slide ${i + 1}`);
    dot.addEventListener("click", () => goToIndex(i, true));
    dotsWrap.appendChild(dot);
  });

  // Buttons
  prevBtn.addEventListener("click", () => goToIndex(idx - 1, true));
  nextBtn.addEventListener("click", () => goToIndex(idx + 1, true));

  // Pause on hover/focus (desktop)
  viewport.addEventListener("mouseenter", stop);
  viewport.addEventListener("mouseleave", start);
  viewport.addEventListener("focusin", stop);
  viewport.addEventListener("focusout", start);

  // Swipe/drag: use pointer events, but do not steal clicks from links/controls, ignore iframe
  let down = false;
  let startX = 0;
  let startLeft = 0;

  function isInteractiveTarget(el) {
    return !!(el && el.closest && el.closest("a, button, input, select, textarea, label"));
  }

  viewport.addEventListener("pointerdown", (e) => {
    if (e.target.closest && e.target.closest("iframe")) return;
    if (isInteractiveTarget(e.target)) return;

    down = true;
    startX = e.clientX;
    startLeft = viewport.scrollLeft;
    stop();
    viewport.setPointerCapture?.(e.pointerId);
  });

  viewport.addEventListener("pointermove", (e) => {
    if (!down) return;
    const dx = e.clientX - startX;
    viewport.scrollLeft = startLeft - dx;
  });

  viewport.addEventListener("pointerup", () => {
    if (!down) return;
    down = false;

    const w = slideWidth();
    if (w < 10) {
      restart();
      return;
    }

    // Snap to nearest physical slide, then map to idx (exclude embed)
    const physical = Math.round(viewport.scrollLeft / w); // 0 = embed
    const linkPhysical = Math.max(1, physical); // clamp at first link slide
    const newIdx = (linkPhysical - 1 + slides.length) % slides.length;
    goToIndex(newIdx, true);
  });

  viewport.addEventListener("pointercancel", () => {
    down = false;
    restart();
  });

  // Trackpad/scroll wheel on desktop: update dots/chip when user scrolls
  let scrollT = null;
  viewport.addEventListener("scroll", () => {
    if (!isBooted) return;
    if (isProgrammaticScroll) return;

    clearTimeout(scrollT);
    scrollT = setTimeout(() => {
      const w = slideWidth();
      if (w < 10) return;

      const physical = Math.round(viewport.scrollLeft / w); // 0 embed
      const linkPhysical = Math.max(1, physical);
      const newIdx = (linkPhysical - 1 + slides.length) % slides.length;

      if (newIdx !== idx) {
        idx = newIdx;
        setChipAndDots();
        restart();
      }
    }, 80);
  });

  // Keep current slide on resize without animation
  function onResizeSnap() {
    const w = slideWidth();
    if (w < 10) return;
    const left = (idx + 1) * w;
    viewport.scrollTo({ left, behavior: "auto" });
  }
  window.addEventListener("resize", () => {
    // give layout a beat
    setTimeout(onResizeSnap, 60);
  });

  // BOOT: wait until viewport has a real width
  function boot() {
    const w = slideWidth();
    if (w < 10) {
      requestAnimationFrame(boot);
      return;
    }

    isBooted = true;
    idx = 0;
    setChipAndDots();

    // Jump to first link slide (physical 1)
    viewport.scrollTo({ left: 1 * w, behavior: "auto" });
    start();
  }

  // Fonts can shift widths on desktop; wait for them if available
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(() => boot());
  } else {
    boot();
  }
});

/* ─────────────────────────────────────────────────────────────
   STUDIO SLIDESHOW
───────────────────────────────────────────────────────────── */
onReady(function () {
  const images = [
    "/assets/images/S1.jpeg","/assets/images/S2.jpeg","/assets/images/S3.jpeg",
    "/assets/images/S4.jpeg","/assets/images/S5.jpeg","/assets/images/S6.jpeg",
    "/assets/images/S7.jpeg","/assets/images/S8.jpeg","/assets/images/S9.jpeg",
    "/assets/images/S10.jpeg","/assets/images/S11.jpeg","/assets/images/S12.jpeg",
    "/assets/images/S13.jpeg","/assets/images/S14.jpeg","/assets/images/S15.jpeg",
    "/assets/images/S16.jpeg","/assets/images/S17.jpeg"
  ];

  const imgA = document.getElementById("imgA");
  const imgB = document.getElementById("imgB");
  if (!imgA || !imgB) return;

  let i = 0;
  let showingA = true;

  function preload(src) {
    return new Promise((resolve) => {
      const im = new Image();
      im.onload = () => resolve(src);
      im.onerror = () => resolve(src);
      im.src = src;
    });
  }

  async function swap() {
    const nextSrc = images[i % images.length];
    i++;
    await preload(nextSrc);

    const show = showingA ? imgB : imgA;
    const hide = showingA ? imgA : imgB;

    show.src = nextSrc;

    requestAnimationFrame(() => {
      show.classList.add("show");
      hide.classList.remove("show");
      showingA = !showingA;
    });
  }

  imgA.src = images[0];
  imgA.classList.add("show");
  i = 1;

  setInterval(swap, 4200);
});

/* ─────────────────────────────────────────────────────────────
   VIDEO SEARCH / FILTER / SORT
───────────────────────────────────────────────────────────── */
onReady(function () {
  const grid = document.getElementById("videoGrid");
  const q = document.getElementById("q");
  const artist = document.getElementById("artist");
  const sort = document.getElementById("sort");
  const empty = document.getElementById("empty");
  if (!grid || !q || !artist || !sort || !empty) return;

  const cards = Array.from(grid.querySelectorAll(".vcard"));
  if (!cards.length) return;

  const names = new Set();
  cards.forEach((c) => {
    const a = (c.getAttribute("data-artist") || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    a.forEach((x) => names.add(x));
  });

  Array.from(names)
    .sort((a, b) => a.localeCompare(b))
    .forEach((n) => {
      const opt = document.createElement("option");
      opt.value = n;
      opt.textContent = n;
      artist.appendChild(opt);
    });

  function apply() {
    const term = (q.value || "").trim().toLowerCase();
    const who = (artist.value || "").trim();
    const mode = sort.value;

    let filtered = cards.filter((c) => {
      const t = (c.getAttribute("data-title") || "").toLowerCase();
      const a = (c.getAttribute("data-artist") || "").toLowerCase();
      const okTerm = !term || t.includes(term) || a.includes(term);
      const okArtist =
        !who ||
        (c.getAttribute("data-artist") || "")
          .split(",")
          .map((s) => s.trim())
          .includes(who);
      return okTerm && okArtist;
    });

    const byDate = (x) => x.getAttribute("data-date") || "1900-01-01";

    if (mode === "oldest") filtered.sort((a, b) => byDate(a).localeCompare(byDate(b)));
    else if (mode === "az")
      filtered.sort((a, b) =>
        (a.getAttribute("data-title") || "").localeCompare(b.getAttribute("data-title") || "")
      );
    else if (mode === "za")
      filtered.sort((a, b) =>
        (b.getAttribute("data-title") || "").localeCompare(a.getAttribute("data-title") || "")
      );
    else filtered.sort((a, b) => byDate(b).localeCompare(byDate(a)));

    grid.innerHTML = "";
    filtered.forEach((c) => grid.appendChild(c));
    empty.style.display = filtered.length ? "none" : "block";
  }

  q.addEventListener("input", apply);
  artist.addEventListener("change", apply);
  sort.addEventListener("change", apply);

  apply();
});

/* ─────────────────────────────────────────────────────────────
   TICKER (duplicate + measure + animate exact px distance)
───────────────────────────────────────────────────────────── */
onReady(function () {
  const track = document.getElementById("tickerTrack");
  const item = document.getElementById("tickerItem");
  if (!track || !item) return;

  function rebuild() {
    while (track.children.length > 1) track.removeChild(track.lastChild);

    const viewportW = window.innerWidth || 1200;
    let totalW = item.getBoundingClientRect().width;

    while (totalW < viewportW * 2) {
      const clone = item.cloneNode(true);
      clone.removeAttribute("id");
      clone.setAttribute("aria-hidden", "true");
      track.appendChild(clone);
      totalW += clone.getBoundingClientRect().width;
    }

    const baseW = item.getBoundingClientRect().width;
    const pxPerSec = 90;
    const dur = Math.max(16, Math.min(40, baseW / pxPerSec));

    const old = document.getElementById("tickerStyle");
    if (old) old.remove();

    const style = document.createElement("style");
    style.id = "tickerStyle";
    style.textContent = `
      @keyframes tickerMovePx {
        0% { transform: translateX(0); }
        100% { transform: translateX(-${baseW}px); }
      }
      #tickerTrack { animation: tickerMovePx ${dur}s linear infinite; }
    `;
    document.head.appendChild(style);
  }

  window.addEventListener("load", rebuild);
  window.addEventListener("resize", () => {
    setTimeout(rebuild, 120);
  });
  rebuild();
});
