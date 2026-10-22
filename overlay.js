// overlay.js: injected by webcrawler.py into every page the browser opens.
// Draws the crawler, watches which links are visible as you scroll, and reports each new link to Python
// through the exposed binding window.__wc_capture. Python prepends:  window.__WC_CONFIG = { skin, mode, summoned };
(() => {
  "use strict";
  if (window.top !== window || window.__wcLoaded) return;
  window.__wcLoaded = true;
  const CFG = Object.assign({ skin: "sentinel", mode: "view", summoned: true }, window.__WC_CONFIG || {});
  const SKIN_IDS = ["sentinel", "hacker", "spider", "packet", "lock", "drone", "radar", "bot"];
  const BAND = [0.4, 0.6];

  const O = "#0b1220"; // outline / dark
  const legs = (cls, pts, c, w) => `<g class="${cls}" fill="none" stroke="${c}" stroke-width="${w || 2.4}" stroke-linecap="round" stroke-linejoin="round">${pts.map((p) => `<polyline points="${p}"/>`).join("")}</g>`;

  const ART = {
    sentinel: () => `<svg viewBox="0 0 64 64" aria-hidden="true">
      <g class="float"><path d="M32 4l22 8v16c0 14-9 24-22 30C19 52 10 42 10 28V12z" fill="#0d2540" stroke="#3fd1ff" stroke-width="2.6" stroke-linejoin="round"/>
      <path d="M32 9.5l17 6.2V28c0 11-7 19-17 24.4C22 47 15 39 15 28V15.7z" fill="none" stroke="#3fd1ff" stroke-width="1" opacity=".45"/>
      <path d="M18 31q14-13 28 0q-14 13-28 0z" fill="#06121f" stroke="#43ffb1" stroke-width="2"/>
      <g class="scan"><circle cx="32" cy="31" r="5.2" fill="#43ffb1"/><circle cx="32" cy="31" r="2.3" fill="${O}"/><circle cx="30.6" cy="29.6" r="1" fill="#fff"/></g>
      <path d="M24 44l4 3 4-3 4 3 4-3" fill="none" stroke="#3fd1ff" stroke-width="1.6" stroke-linecap="round" opacity=".7"/></g>
      <path d="M22 59h20" stroke="#3fd1ff" stroke-width="2" stroke-linecap="round" opacity=".35"/></svg>`,

    hacker: () => `<svg viewBox="0 0 64 64" aria-hidden="true">
      <g class="bob"><path d="M32 5c-10 0-16 7-16 16 0 4 1 7 3 10l-5 9h36l-5-9c2-3 3-6 3-10 0-9-6-16-16-16z" fill="#161d33" stroke="#43ffb1" stroke-width="2.2" stroke-linejoin="round"/>
      <path d="M22 22c0-6 4-10 10-10s10 4 10 10v6c0 4-4 7-10 7s-10-3-10-7z" fill="#02060d"/>
      <g class="blink"><ellipse cx="27.5" cy="25" rx="3" ry="1.9" fill="#43ffb1"/><ellipse cx="36.5" cy="25" rx="3" ry="1.9" fill="#43ffb1"/></g>
      <path d="M28 31h8" stroke="#43ffb1" stroke-width="1.4" stroke-linecap="round" opacity=".7"/>
      <rect x="15" y="43" width="34" height="13" rx="2.6" fill="#0d1424" stroke="#3fd1ff" stroke-width="2"/>
      <text x="32" y="53" text-anchor="middle" font-family="Consolas,monospace" font-size="9" font-weight="700" fill="#43ffb1">&lt;/&gt;</text></g></svg>`,

    spider: () => `<svg viewBox="0 0 64 64" aria-hidden="true">
      ${legs("legA", ["25,27 12,16 5,26", "24,33 8,32 3,43", "25,39 12,47 8,59", "27,44 19,54 17,61"], "#3fd1ff", 2)}
      ${legs("legB", ["39,27 52,16 59,26", "40,33 56,32 61,43", "39,39 52,47 56,59", "37,44 45,54 47,61"], "#3fd1ff", 2)}
      <g fill="#ff3df0"><circle cx="12" cy="16" r="1.8"/><circle cx="52" cy="16" r="1.8"/><circle cx="8" cy="32" r="1.8"/><circle cx="56" cy="32" r="1.8"/></g>
      <g class="bob"><path d="M32 29l9 5v11l-9 6-9-6V34z" fill="#0d1b33" stroke="#3fd1ff" stroke-width="2" stroke-linejoin="round"/>
      <path d="M32 34v12M26 38l6 3 6-3" stroke="#43ffb1" stroke-width="1.4" fill="none" stroke-linecap="round"/><circle cx="32" cy="41" r="1.8" fill="#43ffb1"/>
      <path d="M26 21l6-5 6 5-2 7h-8z" fill="#122a4a" stroke="#3fd1ff" stroke-width="2" stroke-linejoin="round"/>
      <circle class="blink" cx="29.2" cy="22.2" r="1.7" fill="#ff3df0"/><circle class="blink" cx="34.8" cy="22.2" r="1.7" fill="#ff3df0"/></g></svg>`,

    packet: () => `<svg viewBox="0 0 64 64" aria-hidden="true">
      <g class="float"><path d="M32 6l22 12.4v24.8L32 55.6 10 43.2V18.4z" fill="#0d1b33" stroke="#3fd1ff" stroke-width="2.4" stroke-linejoin="round"/>
      <path d="M10 18.4L32 31l22-12.6M32 31v24.6" stroke="#3fd1ff" stroke-width="1.8" fill="none" stroke-linejoin="round"/>
      <g font-family="Consolas,monospace" font-weight="700" font-size="7.5" fill="#43ffb1"><text x="13" y="30" transform="rotate(30 13 30)">0110</text><text x="39" y="35" transform="rotate(-30 39 35)">1011</text><text x="23" y="20" transform="scale(1 .58) translate(10 14)">SYN</text></g>
      <g class="blink"><circle cx="32" cy="43" r="2.4" fill="#ff3df0"/></g></g>
      <g class="spin" style="animation-duration:3.4s"><circle cx="32" cy="32" r="29" fill="none" stroke="#43ffb1" stroke-width="1.2" stroke-dasharray="2 9" opacity=".7"/></g></svg>`,

    lock: () => `<svg viewBox="0 0 64 64" aria-hidden="true">
      <g class="bob"><g class="shackle"><path d="M21 28V19a11 11 0 0 1 22 0v9" fill="none" stroke="#c9d4ea" stroke-width="5" stroke-linecap="round"/></g>
      <rect x="12" y="27" width="40" height="27" rx="5" fill="#ffd24a" stroke="${O}" stroke-width="2"/>
      <rect x="12" y="27" width="40" height="8" rx="5" fill="#fff0b8" opacity=".35"/>
      <circle cx="32" cy="39.5" r="4.4" fill="${O}"/><path d="M30 42l-1.4 7h6.8L34 42z" fill="${O}"/><circle class="blink" cx="32" cy="39.5" r="1.8" fill="#ff6b6b"/></g>
      ${legs("legA", ["23,54 21,61"], "#c9d4ea", 3)}${legs("legB", ["41,54 43,61"], "#c9d4ea", 3)}</svg>`,

    drone: () => `<svg viewBox="0 0 64 64" aria-hidden="true">
      <g class="float">
      <path d="M22 30l-10-8M42 30l10-8" stroke="#9fb4ff" stroke-width="2.6" stroke-linecap="round"/>
      <ellipse class="rotor" cx="10" cy="20" rx="9" ry="2.6" fill="#3fd1ff" opacity=".75"/><ellipse class="rotor" cx="54" cy="20" rx="9" ry="2.6" fill="#3fd1ff" opacity=".75"/>
      <path d="M10 20v3M54 20v3" stroke="#9fb4ff" stroke-width="2"/>
      <rect x="20" y="28" width="24" height="14" rx="6" fill="#1b2a4a" stroke="#3fd1ff" stroke-width="2"/>
      <circle cx="32" cy="35" r="5.2" fill="${O}" stroke="#43ffb1" stroke-width="1.5"/><circle cx="32" cy="35" r="2" fill="#ff3df0"/><circle class="blink" cx="25" cy="31.5" r="1.3" fill="#ff6b6b"/>
      <path d="M24 44l-3 8M40 44l3 8M19 52h6M39 52h6" stroke="#9fb4ff" stroke-width="2.2" stroke-linecap="round"/></g>
      <ellipse cx="32" cy="60" rx="12" ry="2.4" fill="#000" opacity=".28"/></svg>`,

    radar: () => `<svg viewBox="0 0 64 64" aria-hidden="true">
      <circle cx="32" cy="32" r="27" fill="#07281f" stroke="#43ffb1" stroke-width="2.4"/>
      <circle cx="32" cy="32" r="18" fill="none" stroke="#43ffb1" stroke-width="1.2" opacity=".6"/><circle cx="32" cy="32" r="9" fill="none" stroke="#43ffb1" stroke-width="1.2" opacity=".6"/>
      <path d="M32 5v54M5 32h54" stroke="#43ffb1" stroke-width="1" opacity=".4"/>
      <g class="spin" style="animation-duration:1.8s"><path d="M32 32L32 5A27 27 0 0 1 51 13z" fill="#43ffb1" opacity=".38"/><path d="M32 32V5" stroke="#b9ffe0" stroke-width="2" stroke-linecap="round"/></g>
      <circle class="blink" cx="43" cy="22" r="2.4" fill="#ffd24a"/><circle class="blink" style="animation-delay:.5s" cx="21" cy="40" r="2" fill="#ff6b6b"/><circle cx="32" cy="32" r="2.6" fill="#b9ffe0"/></svg>`,

    bot: () => `<svg viewBox="0 0 64 64" aria-hidden="true">
      <g class="bob"><path d="M32 8v7" stroke="#9fb4ff" stroke-width="2.4" stroke-linecap="round"/><circle class="blink" cx="32" cy="7" r="3.2" fill="#ff3df0"/>
      <rect x="14" y="15" width="36" height="25" rx="8" fill="#1b2a4a" stroke="#3fd1ff" stroke-width="2"/>
      <rect x="19" y="21" width="26" height="13" rx="5" fill="${O}"/>
      <circle cx="26" cy="27.5" r="3.4" fill="#43ffb1"/><circle cx="38" cy="27.5" r="3.4" fill="#43ffb1"/>
      <rect x="18" y="42" width="28" height="11" rx="4" fill="#142241" stroke="#3fd1ff" stroke-width="2"/>
      <path d="M24 46h16" stroke="#3fd1ff" stroke-width="1.8" stroke-linecap="round"/>
      <rect x="9" y="42" width="7" height="3.6" rx="1.8" fill="#9fb4ff"/><rect x="48" y="42" width="7" height="3.6" rx="1.8" fill="#9fb4ff"/></g>
      <g><rect x="14" y="54" width="14" height="7" rx="3.5" fill="#222c45" stroke="#9fb4ff" stroke-width="1.5"/><rect x="36" y="54" width="14" height="7" rx="3.5" fill="#222c45" stroke="#9fb4ff" stroke-width="1.5"/>
      <g class="spin"><circle cx="21" cy="57.5" r="1.2" fill="#9fb4ff"/></g><g class="spin"><circle cx="43" cy="57.5" r="1.2" fill="#9fb4ff"/></g></g></svg>`
  };

  const SPRITE_CSS = `@keyframes cw-beam{0%{opacity:1}100%{opacity:0}}
.cw-ping{position:absolute;font:800 13px system-ui;color:#0b3d2b;background:#43ffb1;padding:1px 8px;border-radius:999px;box-shadow:0 2px 10px rgba(0,0,0,.35);animation:cw-ping .9s ease-out forwards;white-space:nowrap}
@keyframes cw-ping{0%{opacity:0;transform:translateY(6px) scale(.8)}20%{opacity:1}100%{opacity:0;transform:translateY(-26px) scale(1)}}
.cw-sprite{position:absolute;left:0;top:0;width:68px;height:68px;transition:transform .42s cubic-bezier(.3,.9,.3,1);will-change:transform;filter:drop-shadow(0 6px 8px rgba(0,0,0,.45))}
.cw-sprite .cw-in{width:100%;height:100%}
.cw-sprite svg{width:100%;height:100%;overflow:visible}
.cw-sprite.summon .cw-in{animation:cw-summon .9s cubic-bezier(.2,1.2,.3,1)}
.cw-sprite.summon::before{content:"";position:absolute;inset:-14px;border-radius:50%;border:3px solid #43ffb1;animation:cw-ring .9s ease-out forwards}
.cw-sprite.poof .cw-in{animation:cw-poof .45s ease-in forwards}
@keyframes cw-summon{0%{transform:scale(0) rotate(-200deg);opacity:0}60%{opacity:1}100%{transform:scale(1) rotate(0)}}
@keyframes cw-ring{0%{transform:scale(.2);opacity:1}100%{transform:scale(2.2);opacity:0}}
@keyframes cw-poof{0%{transform:scale(1);opacity:1}100%{transform:scale(0) rotate(160deg);opacity:0}}
.cw-sprite.snap .cw-in{animation:cw-snap .28s ease-out}
@keyframes cw-snap{0%{transform:scale(1)}40%{transform:scale(1.28)}100%{transform:scale(1)}}

/* sprite art: every skin uses these helper classes */
.cw-sprite svg *{transform-box:fill-box;transform-origin:center}
.cw-sprite .bob{animation:cw-bob 1.4s ease-in-out infinite}
.cw-sprite .legA{animation:cw-legA .32s linear infinite alternate;transform-origin:50% 50%}
.cw-sprite .legB{animation:cw-legA .32s linear infinite alternate-reverse;transform-origin:50% 50%}
.cw-sprite .spin{animation:cw-spin 2.6s linear infinite}
.cw-sprite .rotor{animation:cw-rotor .12s linear infinite alternate}
.cw-sprite .blink{animation:cw-blink 1.1s steps(2) infinite}
.cw-sprite .float{animation:cw-float 2.2s ease-in-out infinite}
.cw-sprite .wave{animation:cw-wave .9s ease-in-out infinite alternate}
.cw-sprite .feel{animation:cw-feel .6s ease-in-out infinite alternate}
.cw-sprite .scan{animation:cw-scan 1.6s ease-in-out infinite alternate}
.cw-sprite .shackle{animation:cw-shackle 1.8s ease-in-out infinite}
@keyframes cw-bob{50%{transform:translateY(-3px)}}
@keyframes cw-legA{from{transform:rotate(-7deg)}to{transform:rotate(7deg)}}
@keyframes cw-spin{to{transform:rotate(360deg)}}
@keyframes cw-rotor{from{transform:scaleX(1)}to{transform:scaleX(.35)}}
@keyframes cw-blink{50%{opacity:.25}}
@keyframes cw-float{50%{transform:translateY(-5px)}}
@keyframes cw-wave{from{transform:scaleY(1) translateY(0)}to{transform:scaleY(.82) translateY(1px)}}
@keyframes cw-feel{from{transform:rotate(-9deg)}to{transform:rotate(9deg)}}
@keyframes cw-scan{from{transform:translateX(-5px)}to{transform:translateX(5px)}}
@keyframes cw-shackle{0%,55%,100%{transform:translateY(0)}70%,85%{transform:translateY(-5px)}}
@media (prefers-reduced-motion:reduce){.cw-sprite *,.cw-sprite{animation:none!important;transition:none!important}.cw-ping{animation-duration:.01s}}
`;
  const HOST_CSS = `
    :host{all:initial}
    .layer{position:fixed;inset:0;pointer-events:none;z-index:2147483647;font-family:system-ui,Segoe UI,Arial,sans-serif}
    .hud{position:fixed;left:12px;bottom:12px;display:flex;gap:10px;align-items:center;padding:7px 12px;border-radius:999px;background:rgba(8,12,22,.88);color:#eaf3ff;font-size:12.5px;border:1px solid rgba(255,255,255,.22);box-shadow:0 6px 20px rgba(0,0,0,.4);pointer-events:auto;user-select:none}
    .hud b{color:#43ffb1;font-variant-numeric:tabular-nums}.hud small{color:#9fb0cc}
    .line{position:fixed;left:0;right:0;height:0;border-top:2px dashed rgba(63,209,255,.9);box-shadow:0 0 12px rgba(63,209,255,.8)}
    .cw-sprite{position:fixed}.cw-ping{position:fixed}
    .hide{display:none!important}
    svg.beam{position:fixed;inset:0;width:100%;height:100%}
    svg.beam line{stroke:#43ffb1;stroke-width:2.4;stroke-linecap:round;stroke-dasharray:5 5;opacity:0}
    svg.beam line.fire{animation:cw-beam .5s ease-out}
  `;
  const PAGE_CSS = "a[data-wc],area[data-wc]{outline:2px solid #1fbf84!important;outline-offset:2px!important;background-color:rgba(67,255,177,.18)!important}" +
    "a[data-wc-new],area[data-wc-new]{outline-color:#ff9d00!important;background-color:rgba(255,157,0,.45)!important}";

  const sheet = (css) => { try { const s = new CSSStyleSheet(); s.replaceSync(css); return s; } catch (e) { return null; } };
  const NS = "http://www.w3.org/2000/svg";

  function start() {
    if (document.getElementById("__wc_host")) return;
    // page highlight styles (adoptedStyleSheets are not blocked by a page's CSP)
    const ps = sheet(PAGE_CSS);
    if (ps) document.adoptedStyleSheets = [...document.adoptedStyleSheets, ps];
    else { const st = document.createElement("style"); st.textContent = PAGE_CSS; document.documentElement.appendChild(st); }

    const host = document.createElement("div"); host.id = "__wc_host";
    const root = host.attachShadow({ mode: "closed" });
    const rs = [sheet(HOST_CSS), sheet(SPRITE_CSS)].filter(Boolean);
    if (rs.length === 2) root.adoptedStyleSheets = rs;
    else { const st = document.createElement("style"); st.textContent = HOST_CSS + SPRITE_CSS; root.appendChild(st); }

    const layer = document.createElement("div"); layer.className = "layer";
    const line = document.createElement("div"); line.className = "line hide";
    const svg = document.createElementNS(NS, "svg"); svg.setAttribute("class", "beam");
    const beam = document.createElementNS(NS, "line"); svg.appendChild(beam);
    const sprite = document.createElement("div"); sprite.className = "cw-sprite hide";
    const spriteIn = document.createElement("div"); spriteIn.className = "cw-in"; sprite.appendChild(spriteIn);
    const hud = document.createElement("div"); hud.className = "hud";
    const hudCount = document.createElement("b"); hudCount.textContent = "0";
    const hudTxt = document.createElement("span"); hudTxt.textContent = "links captured";
    const hudHelp = document.createElement("small"); hudHelp.textContent = "Alt+Shift+C summon/dismiss · S look · M mode";
    hud.append(hudCount, hudTxt, hudHelp);
    layer.append(line, svg, sprite, hud); root.appendChild(layer);
    document.documentElement.appendChild(host);

    // keep the host last in <html> even if the page re-renders
    new MutationObserver(() => { if (host.parentNode !== document.documentElement) document.documentElement.appendChild(host); }).observe(document.documentElement, { childList: true });

    let summoned = false, skin = SKIN_IDS.includes(CFG.skin) ? CFG.skin : "sentinel", mode = CFG.mode === "line" ? "line" : "view";
    let hops = [], hopping = false, timer = 0;

    const band = () => (mode === "line" ? BAND : null);
    const setSkin = (id) => { skin = id; spriteIn.innerHTML = ART[id] ? ART[id]() : ART.sentinel(); };
    const move = (x, y) => { sprite.style.left = "0"; sprite.style.top = "0"; sprite.style.transform = `translate(${Math.round(x)}px,${Math.round(y)}px)`; };
    const park = () => { const b = band(); move(Math.max(8, innerWidth - 110), (b ? (b[0] + b[1]) / 2 : 0.5) * innerHeight - 34); };
    const showLine = () => { const b = band(); line.classList.toggle("hide", !(summoned && b)); if (b) line.style.top = ((b[0] + b[1]) / 2) * innerHeight + "px"; };
    const fire = (cls) => { sprite.classList.remove(cls); void sprite.offsetWidth; sprite.classList.add(cls); };

    function summon() {
      summoned = true; sprite.classList.remove("hide", "poof"); park(); fire("summon"); setTimeout(() => sprite.classList.remove("summon"), 1000);
      showLine(); scan();
    }
    function dismiss() { summoned = false; hops = []; sprite.classList.remove("summon"); sprite.classList.add("poof"); setTimeout(() => { if (!summoned) sprite.classList.add("hide"); }, 460); showLine(); }

    function ping(x, y) {
      const d = document.createElement("div"); d.className = "cw-ping"; d.textContent = "+1"; d.style.left = Math.max(4, x) + "px"; d.style.top = Math.max(4, y) + "px";
      layer.appendChild(d); setTimeout(() => d.remove(), 950);
    }
    function runHops() {
      if (hopping) return;
      const next = hops.shift(); if (!next) return;
      hopping = true;
      const r = next.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) {
        const tx = Math.min(innerWidth - 76, Math.max(4, r.right + 6)), ty = r.top + r.height / 2 - 34, cx = r.left + r.width / 2, cy = r.top + r.height / 2;
        move(tx, ty);
        setTimeout(() => {
          beam.setAttribute("x1", tx + 34); beam.setAttribute("y1", ty + 34); beam.setAttribute("x2", cx); beam.setAttribute("y2", cy);
          beam.classList.remove("fire"); void beam.getBoundingClientRect(); beam.classList.add("fire"); fire("snap"); ping(cx - 10, cy - 24);
        }, 260);
      }
      setTimeout(() => { hopping = false; if (hops.length) runHops(); else setTimeout(() => { if (!hops.length && summoned) park(); }, 700); }, 340);
    }

    function seen(el) {
      const r = el.getBoundingClientRect(), b = band(), lo = b ? b[0] * innerHeight : 0, hi = b ? b[1] * innerHeight : innerHeight;
      if (!(r.width > 0 && r.height > 0) || !(r.bottom > lo && r.top < hi && r.right > 0 && r.left < innerWidth)) return false;
      if (el.checkVisibility && !el.checkVisibility({ visibilityProperty: true })) return false;
      return true;
    }
    const hrefOf = (el) => { try { const u = new URL(el.getAttribute("href"), document.baseURI); return /^(javascript|data|vbscript|blob):/i.test(u.protocol) ? "" : u.href; } catch (e) { return ""; } };
    function labelOf(el) {
      const img = el.querySelector && el.querySelector("img");
      return (el.textContent || "").trim() || el.getAttribute("aria-label") || el.getAttribute("title") || (img && img.alt) || el.getAttribute("alt") || "";
    }
    async function scan() {
      timer = 0;
      if (!summoned) return;
      const batch = [], els = [];
      for (const el of document.querySelectorAll("a[href],area[href]")) {
        if (el.__wcDone || !seen(el)) continue;
        el.__wcDone = true;
        const href = hrefOf(el); if (!href) continue;
        el.setAttribute("data-wc", "1"); el.setAttribute("data-wc-new", "1"); setTimeout(() => el.removeAttribute("data-wc-new"), 1000);
        batch.push({ href, text: labelOf(el).replace(/\s+/g, " ").trim().slice(0, 120), rel: el.getAttribute("rel") || "", page: location.href });
        els.push(el);
      }
      if (!batch.length) return;
      for (const el of els) if (hops.length < 8) hops.push(el);
      runHops();
      try { const total = await window.__wc_capture(JSON.stringify(batch)); if (typeof total === "number") hudCount.textContent = String(total); } catch (e) { /* python side gone */ }
    }
    const schedule = () => { if (!timer) timer = setTimeout(scan, 70); };

    addEventListener("scroll", schedule, { capture: true, passive: true });
    addEventListener("resize", () => { if (summoned) { park(); showLine(); } schedule(); });
    new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
    setInterval(schedule, 1000);
    addEventListener("keydown", (e) => {
      if (!(e.altKey && e.shiftKey)) return;
      const k = e.key.toLowerCase();
      if (k === "c") { summoned ? dismiss() : summon(); }
      else if (k === "s") { setSkin(SKIN_IDS[(SKIN_IDS.indexOf(skin) + 1) % SKIN_IDS.length]); fire("snap"); }
      else if (k === "m") { mode = mode === "line" ? "view" : "line"; showLine(); if (summoned) { park(); schedule(); } }
    }, true);

    const setMode = (m) => { mode = m === "line" ? "line" : "view"; showLine(); if (summoned) { park(); schedule(); } };
    const reset = () => { for (const el of document.querySelectorAll("[data-wc]")) { delete el.__wcDone; el.removeAttribute("data-wc"); } hops = []; schedule(); };
    window.__wc_api = { summon, dismiss, setSkin, setMode, reset, scan: schedule, state: () => ({ summoned, skin, mode }) };
    setSkin(skin);
    if (CFG.summoned) summon();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true }); else start();
})();
