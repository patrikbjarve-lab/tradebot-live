/* Tradebot Live – read-only terminal. Each sleeve is one AES-256-GCM file (data/<id>.enc.json) in the
   common sleeve schema; decrypted locally with a PBKDF2-SHA256 key. Adding a sleeve = adding its file. */
(() => {
  "use strict";
  const SLEEVES = [{ id: "etf", name: "ETF" }, { id: "krypto", name: "KRYPTO" }, { id: "aktier_momentum", name: "MOMENTUM" }, { id: "aktier_tech", name: "TECH" }, { id: "aktier_usd1000", name: "USA $1000" }];
  const VIEWS = [{ id: "total", name: "TOTALT" }, { id: "risk", name: "RISK" }, { id: "status", name: "STATUS" }, { id: "logg", name: "LOGG" }];
  const SOON_TAPE = [];
  const STRUKEN = "Swing och intraday är strukna (Onedin 21 okt 12:49) och arkiverade – laddas aldrig, inget kapital.";
  const REFRESH_MS = 60_000, KEY_SLOT = "tbl.key.v1", MIN_DAYS = 90;
  const LW = window.LightweightCharts;
  const $ = (id) => document.getElementById(id);
  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const tob64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const TZOFF = () => -new Date().getTimezoneOffset() * 60;
  let key = null, keySalt = null, timer = null, failing = false;
  let data = {}, firstRender = true, active = "etf";
  const prev = {}, seen = {}, charts = {}, views = {};

  // ------------------------------------------------------------ formatting (sv-SE)
  const nf = (d) => new Intl.NumberFormat("sv-SE", { minimumFractionDigits: d, maximumFractionDigits: d });
  const money = (x, c = "SEK", d = 0) => (x == null ? "–" : nf(d).format(x) + (c === "SEK" ? " kr" : " " + c));
  const pct = (x, d = 2, sign = true) => (x == null || isNaN(x) ? "–" : (sign && x > 0 ? "+" : "") + nf(d).format(x * 100) + " %");
  const num = (x, d = 2) => (x == null ? "–" : nf(d).format(x));
  const ud = (x) => (x > 1e-9 ? "up" : x < -1e-9 ? "dn" : "");
  const dt = (s, o) => (s && /^\d{4}-\d\d-\d\d$/.test(String(s)) ? String(s) : s ? new Date(s).toLocaleString("sv-SE", o || { dateStyle: "short", timeStyle: "short" }) : "–");
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const mins = (s) => (s ? (Date.now() - new Date(s).getTime()) / 60000 : Infinity);
  const ago = (s) => { const m = mins(s); if (!isFinite(m)) return "–"; if (m < 1) return "nyss"; if (m < 60) return Math.round(m) + " min sedan";
    const h = m / 60; return h < 24 ? `${Math.floor(h)} h ${Math.round(m % 60)} min sedan` : `${Math.round(h / 24)} d sedan`; };
  const until = (s) => { const m = -mins(s); if (!isFinite(m)) return ""; if (m < 0) return "nu"; const d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60);
    return d ? `om ${d} d ${h} h` : `om ${h} h ${Math.round(m % 60)} min`; };
  const ymd = (epoch) => new Date(epoch * 1000).toLocaleDateString("sv-SE");

  /* write text into an element and flash green/red when the underlying number changes */
  function put(el, k, val, html) {
    if (!el) return;
    el.innerHTML = html;
    if (!firstRender && prev[k] != null && val != null && val !== prev[k]) {
      el.classList.remove("fl-up", "fl-dn"); void el.offsetWidth; el.classList.add(val > prev[k] ? "fl-up" : "fl-dn");
    }
    prev[k] = val;
  }

  // ------------------------------------------------------------ crypto + fetch
  async function deriveKey(pw, salt, iter) {
    const base = await crypto.subtle.importKey("raw", te.encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }
  async function decrypt(blob, k) {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(blob.iv), additionalData: te.encode(blob.aad || "") }, k, b64(blob.ct));
    return JSON.parse(td.decode(pt));
  }
  async function saveKey(k, salt, remember) {
    const v = JSON.stringify({ salt: tob64(salt), k: tob64(await crypto.subtle.exportKey("raw", k)) });
    (remember ? localStorage : sessionStorage).setItem(KEY_SLOT, v);
  }
  async function loadKey() {
    const v = localStorage.getItem(KEY_SLOT) || sessionStorage.getItem(KEY_SLOT);
    if (!v) return null;
    try { const o = JSON.parse(v); return { salt: o.salt, key: await crypto.subtle.importKey("raw", b64(o.k), { name: "AES-GCM" }, false, ["decrypt"]) }; }
    catch { return null; }
  }
  function forget() { localStorage.removeItem(KEY_SLOT); sessionStorage.removeItem(KEY_SLOT); key = null; }
  async function fetchBlob(id) {
    const r = await fetch(`data/${id}.enc.json?t=${Date.now()}`, { cache: "no-store" });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }
  async function fetchAll(k) {
    const out = {};
    for (const s of SLEEVES) {
      const blob = await fetchBlob(s.id);
      if (!blob) continue;
      if (blob.salt !== keySalt) { const e = new Error("salt"); e.name = "OperationError"; throw e; }
      out[s.id] = await decrypt(blob, k);
    }
    const ov = await fetchBlob("overview");
    if (ov && ov.salt === keySalt) out.overview = await decrypt(ov, k);
    return out;
  }

  // ------------------------------------------------------------ lock
  function showLock(msg) { clearInterval(timer); $("app").hidden = true; $("lock").hidden = false; $("lockmsg").textContent = msg || ""; setTimeout(() => $("pw").focus(), 50); }
  $("lockform").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = $("unlock"); btn.disabled = true; $("lockmsg").textContent = "Låser upp…";
    try {
      const blob = await fetchBlob("etf");
      if (!blob) throw new Error("no data");
      const salt = b64(blob.salt);
      const k = await deriveKey($("pw").value, salt, blob.iter);
      keySalt = blob.salt;
      const d = await fetchAll(k);
      key = k; await saveKey(k, salt, $("remember").checked); $("pw").value = "";
      start(d);
    } catch (e) { $("lockmsg").textContent = e && e.name === "OperationError" ? "Fel lösenord." : "Kunde inte hämta data – försök igen."; }
    finally { btn.disabled = false; }
  });
  $("lockbtn").addEventListener("click", () => { forget(); showLock("Sidan är låst."); });

  function start(d) {
    $("lock").hidden = true; $("app").hidden = false;
    buildTabs(); render(d);
    clearInterval(timer); timer = setInterval(refresh, REFRESH_MS);
  }
  async function refresh() {
    try { render(await fetchAll(key)); failing = false; }
    catch (e) { if (e && e.name === "OperationError") { forget(); return showLock("Lösenordet har bytts – logga in igen."); } failing = true; statusBar(); }
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden && key) refresh(); });
  setInterval(() => { $("clock").textContent = new Date().toLocaleTimeString("sv-SE"); if (key && data.etf) statusBar(); }, 1000);

  // ------------------------------------------------------------ tabs
  function buildTabs() {
    const tabs = [...SLEEVES, ...VIEWS];
    $("tabs").innerHTML = tabs.map((t) => `<button class="tab${t.id === active ? " active" : ""}" data-tab="${t.id}" role="tab">${t.name}<small id="tabsub-${t.id}"></small></button>`).join("");
    $("panes").innerHTML = tabs.map((t) => `<section class="pane" id="pane-${t.id}"${t.id === active ? "" : " hidden"}></section>`).join("");
    $("tabs").querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
      active = b.dataset.tab;
      $("tabs").querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
      document.querySelectorAll(".pane").forEach((p) => (p.hidden = p.id !== "pane-" + active));
      requestAnimationFrame(() => ["c", "e", "b"].forEach((k) => { const c = charts[k + active]; if (c) c.ch.timeScale().fitContent(); }));
      statusBar();
    }));
  }

  // ------------------------------------------------------------ status bar + tape
  function heartbeat(s) {
    const m = mins(s.heartbeat_at || s.updated_at), lim = (s.market && s.market.stale_after_min) || 30;
    return { m, c: m < 10 ? "g" : m <= lim ? "a" : "r" };
  }
  function statusBar() {
    const s = (SLEEVES.some((x) => x.id === active) && data[active]) || data.overview || data.etf; if (!s) return;
    const hb = heartbeat(s), staleData = (s.data_stale || []).length > 0;
    const parts = [
      `<span class="badge paper">${esc(s.mode || "PAPPER")}</span>`,
      `<span title="Motorns senaste körning"><i class="dot ${hb.c}"></i>MOTOR <b>${esc(ago(s.heartbeat_at || s.updated_at))}</b></span>`,
      `<span class="${hb.c === "r" || staleData ? "warnline" : ""}">DATA SENAST UPPDATERAD <b>${esc(dt(s.updated_at))}</b>${hb.c === "r" ? " ⚠ INAKTUELL" : ""}${staleData ? " ⚠ " + esc(s.data_stale.join(", ")) : ""}</span>`,
      s.signal && s.signal.next_eval_at ? `<span>NÄSTA BESLUT <b>${esc(dt(s.signal.next_eval_at, { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }))}</b> ${esc(until(s.signal.next_eval_at))}</span>` : "",
      s.market && !s.risk ? `<span>${esc(s.market.name)} <b class="${s.market.is_open ? "up" : "muted"}">${s.market.is_open ? "ÖPPEN" : "STÄNGD"}</b> ${esc(s.market.open)}–${esc(s.market.close)}</span>` : "",
      failing ? `<span class="badline">⚠ KUNDE INTE HÄMTA – VISAR SENASTE</span>` : "",
    ];
    $("statusbar").innerHTML = parts.filter(Boolean).join("");
    $("modebadge").textContent = s.mode || "PAPPER";
  }
  function tape() {
    const q = [];
    Object.values(data).forEach((s) => (s.quotes || []).forEach((x) => { if (x && x.symbol) q.push(x); }));
    const items = q.map((x) => `<span class="tk"><span class="s">${esc(x.symbol.replace(/\.DE$|=X$/, ""))}</span><span class="l" data-q="${esc(x.symbol)}">${num(x.last, x.last > 100 ? 2 : 4)}</span><span class="${ud(x.day_pct)}">${pct(x.day_pct)}</span></span>`)
      .concat(SOON_TAPE.filter((s) => !q.some((x) => x.symbol.startsWith(s))).map((s) => `<span class="tk"><span class="s">${s}</span><span class="soon">kommer snart</span></span>`));
    const html = items.join("");
    const el = $("tape");
    if (el.dataset.h !== html) { el.innerHTML = html + html; el.dataset.h = html; }
    q.forEach((x) => { const k = "q:" + x.symbol; if (!firstRender && prev[k] != null && x.last !== prev[k]) el.querySelectorAll(`[data-q="${CSS.escape(x.symbol)}"]`).forEach((n) => { n.classList.remove("fl-up", "fl-dn"); void n.offsetWidth; n.classList.add(x.last > prev[k] ? "fl-up" : "fl-dn"); }); prev[k] = x.last; });
  }

  // ------------------------------------------------------------ gate (fallback when a sleeve sends none)
  function gateFallback(s) {
    const eq = (s.equity_curve || []).map((p) => p[1]), bm = (s.benchmark_curve || []).map((p) => p[1]);
    const t0 = s.paper_started || (s.equity_curve && s.equity_curve[0] && s.equity_curve[0][0]);
    const days = t0 ? Math.max(0, (Date.now() - new Date(t0)) / 864e5) : 0, enough = days >= MIN_DAYS, prog = Math.min(1, days / MIN_DAYS);
    const wait = `Behöver ${MIN_DAYS} dagar data – ${Math.max(0, Math.ceil(MIN_DAYS - days))} dagar kvar.`;
    const ret = eq.length > 1 ? eq[eq.length - 1] / eq[0] - 1 : 0, bt = s.backtest_stats || {};
    let pk = -Infinity, mdd = 0; eq.forEach((v) => { pk = Math.max(pk, v); mdd = Math.min(mdd, v / pk - 1); });
    const it = [{ label: "Dagar på papper", status: enough ? "pass" : "pending", progress: prog, value: `${days.toFixed(0)} / ${MIN_DAYS} dagar` }];
    if (bt.cagr != null && bt.vol != null) { const t = Math.max(days, 1) / 365.25, e = (1 + bt.cagr) ** t - 1, sd = bt.vol * Math.sqrt(t), ok = ret >= e - 2 * sd && ret <= e + 2 * sd;
      it.push({ label: "Avkastning inom förväntat band", status: enough ? (ok ? "pass" : "fail") : "pending", progress: prog, value: `${pct(ret, 1)} (band ${pct(e - 2 * sd, 1)} … ${pct(e + 2 * sd, 1)})`, note: enough ? "" : wait });
    } else it.push({ label: "Avkastning inom förväntat band", status: "pending", progress: prog, value: pct(ret, 1), note: "Backtest saknas." });
    if (bt.max_dd != null) { const worse = mdd < bt.max_dd; it.push({ label: "Max nedgång inom förväntat", status: worse ? "fail" : enough ? "pass" : "pending", progress: worse ? 1 : prog, value: `${pct(mdd, 1)} (backtest ${pct(bt.max_dd, 1)})`, note: enough ? "" : wait }); }
    else it.push({ label: "Max nedgång inom förväntat", status: "pending", progress: prog, value: pct(mdd, 1), note: "Backtest saknas." });
    if (bm.length > 1) { const br = bm[bm.length - 1] / bm[0] - 1; it.push({ label: "Slår jämförelseindex efter avgifter", status: enough ? (ret >= br ? "pass" : "fail") : "pending", progress: prog, value: `${pct(ret, 1)} mot ${pct(br, 1)}`, note: (enough ? "" : wait + " ") + "Skatt ej inräknad." }); }
    else it.push({ label: "Slår jämförelseindex efter avgifter", status: "pending", progress: prog, value: "–", note: "Ingen jämförelsekurva." });
    it.push({ label: "Inga oförklarade stopp", status: s.halted ? "fail" : "pending", progress: prog, value: s.halted ? "Stopp aktivt" : "–", note: "Sleeven rapporterar ingen stopphistorik." });
    const passed = it.filter((i) => i.status === "pass").length;
    return { passed, total: it.length, summary: `${passed} av ${it.length} krav uppfyllda`, items: it, computed_by: "webbläsaren" };
  }

  // ------------------------------------------------------------ sleeve pane
  const P = (id, cls, title, right, body) => `<article class="pn ${cls}" id="${id}"><div class="ph"><span>${title}</span><span class="r">${right || ""}</span></div><div class="pb">${body || ""}</div></article>`;
  function skeleton(id) {
    return `<div id="halt-${id}" class="haltbar" hidden></div><div class="grid">
      ${P(`pf-${id}`, "s4", "Portfölj", "", `<div class="big num" id="v-${id}">–</div><div class="kv" id="kv-${id}"></div><div class="gauge" id="g-${id}"></div>`)}
      ${P(`sg-${id}`, "s4", "Signal", `<span id="sgr-${id}"></span>`, `<div id="sig-${id}"></div>`)}
      ${P(`gt-${id}`, "s4", "Live-spärr", `<span id="gtr-${id}"></span>`, `<div id="gate-${id}"></div>`)}
      ${P(`ch-${id}`, "s8", `Kurs <span id="chs-${id}" class="muted"></span>`, `<span class="lg"><i style="background:var(--ac)"></i><span id="smal-${id}">snitt</span></span> <span class="seg" id="seg-${id}"><button data-v="d" class="on">DAG</button><button data-v="i">15 MIN</button></span>`, `<div class="chart" id="cc-${id}"></div>`)}
      ${P(`po-${id}`, "s4", "Positioner", "", `<div class="tw" id="pos-${id}"></div>`)}
      ${P(`eq-${id}`, "s6", "Utveckling vs jämförelse", `<span class="lg"><i style="background:var(--up)"></i>Portfölj<i style="background:#94a3b8"></i><span id="bn-${id}">Index</span></span>`, `<div class="chart sm" id="ec-${id}"></div><div class="muted" id="en-${id}" style="font-size:11px;margin-top:4px"></div>`)}
      ${P(`bl-${id}`, "s6", "Order / affärer", `<span id="blr-${id}"></span>`, `<div class="tw" id="blot-${id}"></div>`)}
      ${P(`jo-${id}`, "s6", "Journal", "", `<ol class="jr" id="jr-${id}"></ol>`)}
      ${P(`bt-${id}`, "s6", "Backtest", `<span class="lg"><i style="background:var(--up)"></i>Strategi<i style="background:#94a3b8"></i>Köp &amp; behåll</span>`, `<div class="chart sm" id="btc-${id}"></div><div class="stats" id="bts-${id}"></div>`)}
    </div>`;
  }
  function soonPane(id, name) {
    return `<div class="grid">${P("soon-" + id, "s12", name, "kommer snart", `<div class="soon"><h2>${name} – KOMMER SNART</h2>
      <p>Den här delen av pappershandeln är inte igång ännu. När den publicerar sin ögonblicksbild (samma format som ETF) visas portfölj, signal, live-spärr, kurser och affärer här automatiskt.</p>
      <div class="skel" style="width:70%;margin:14px auto"></div><div class="skel" style="width:50%;margin:8px auto"></div></div>`)}</div>`;
  }

  function renderSleeve(id, s) {
    const pane = $("pane-" + id);
    if (!pane.dataset.built) { pane.innerHTML = skeleton(id); pane.dataset.built = "1"; bindSeg(id); }
    const c = s.currency || "SEK";
    $("tabsub-" + id).innerHTML = `<span class="${ud(s.day_change_pct)}">${pct(s.day_change_pct, 1)}</span>`;
    // halt
    $("halt-" + id).hidden = !s.halted;
    if (s.halted) $("halt-" + id).textContent = `⛔ STOPP AKTIVT – ${s.halted.reason || ""} (${dt(s.halted.ts)})`;
    // portfolio
    put($("v-" + id), id + ":v", s.value, money(s.value, c));
    const dayAbs = s.day_change != null ? s.day_change : null;
    $("kv-" + id).innerHTML = `<span>P/L idag</span><b id="kd-${id}" class="${ud(s.day_change_pct)}"></b>
      <span>Totalt</span><b class="${ud(s.total_change_pct)}">${pct(s.total_change_pct)}${s.start_value ? ` <span class="muted">(start ${money(s.start_value, c)})</span>` : ""}</b>
      <span>Kassa</span><b>${money(s.cash, c)}</b>
      ${s.value_sek != null ? `<span>I SEK</span><b>${money(s.value_sek)}</b>` : ""}
      ${s.fx && s.fx.EURSEK ? `<span>EUR/SEK</span><b>${num(s.fx.EURSEK, 4)}</b>` : ""}
      ${s.fx && s.fx.USDSEK ? `<span>USD/SEK</span><b>${num(s.fx.USDSEK, 4)}</b>` : ""}
      ${s.source_asof ? `<span>Innehav per</span><b class="${mins(s.source_asof) > 30 * 60 ? "am" : ""}">${esc(dt(s.source_asof))}</b>` : ""}`;
    put($("kd-" + id), id + ":d", s.day_change_pct, `${dayAbs != null ? (dayAbs > 0 ? "+" : "") + money(dayAbs, c) + " · " : ""}${pct(s.day_change_pct)}`);
    gauge(id, s.drawdown_pct || 0, s.kill_switch_limit_pct === null ? null : s.kill_switch_limit_pct || -0.15);
    $("ch-" + id).hidden = !s.ohlc; $("po-" + id).classList.toggle("s4", !!s.ohlc); $("po-" + id).classList.toggle("s12", !s.ohlc);
    // signal
    const sg = s.signal || {}, a = (sg.action || "").toUpperCase();
    const ac = /STOPP/.test(a) ? "stop" : /KÖP|AKTIER/.test(a) ? "buy" : /SÄLJ|KASSA/.test(a) ? "sell" : /BEHÅLL/.test(a) ? "hold" : "wait";
    $("sgr-" + id).textContent = sg.asof ? `underlag t.o.m. ${sg.asof}` : "";
    $("sig-" + id).innerHTML = `<span class="act ${ac}">${esc(sg.action || "–")}</span>
      <p class="reason">${esc(sg.reason_sv || "Ingen signal ännu.")}</p>
      <div class="chips">${(sg.details || []).map((d) => `<span class="chip">${esc(d)}</span>`).join("")}</div>
      ${sg.provisional_sv ? `<div class="muted" style="font-size:12px">Preliminärt med senaste kurs: ${esc(sg.provisional_sv)}</div>` : ""}
      ${sg.next_eval_at ? `<div style="margin-top:6px">Nästa beslut: <span class="cd">${esc(dt(sg.next_eval_at, { weekday: "long", day: "numeric", month: "long", hour: "2-digit", minute: "2-digit" }))}</span> <span class="muted">${esc(until(sg.next_eval_at))}</span></div>` : ""}
      ${sg.rule ? `<div class="muted" style="font-size:11px;margin-top:6px">${esc(sg.rule)}</div>` : ""}`;
    // gate
    const g = s.gate || gateFallback(s);
    $("gtr-" + id).textContent = g.computed_by === "webbläsaren" ? "beräknad i webbläsaren" : "";
    $("gate-" + id).innerHTML = `<div class="gsum"><b class="${g.passed === g.total ? "up" : "dn"}">${esc(g.summary || `${g.passed} av ${g.total} krav uppfyllda`)}</b>
      <span class="muted mono" style="font-size:11px">${g.passed === g.total ? "redo för live" : "inte redo för live"}</span></div>` +
      g.items.map((i) => `<div class="gi ${i.status}"><div class="h"><span>${esc(i.label)}</span><span class="gs ${i.status}">${i.status === "pass" ? "✓ OK" : i.status === "fail" ? "✗ EJ OK" : "… VÄNTAR"}</span></div>
        <div class="v">${esc(i.value || "")}</div><div class="bar"><i style="width:${Math.round((i.progress || 0) * 100)}%"></i></div>${i.note ? `<div class="n">${esc(i.note)}</div>` : ""}</div>`).join("");
    // positions
    const rows = (s.holdings || []).map((h) => `<tr><td>${esc(h.symbol)}<span class="nm">${esc(h.name || "")}</span></td><td>${num(h.qty, h.qty % 1 ? 8 : 0)}</td>
      <td data-k>${num(h.price)}${h.price_ccy && h.price_ccy !== c ? " " + esc(h.price_ccy) : ""}</td><td>${money(h.value, c)}</td><td>${pct(h.weight, 1, false)}</td><td class="${ud(h.pnl)}">${h.pnl > 0 ? "+" : ""}${money(h.pnl, c)}</td></tr>`).join("");
    const cw = s.value ? s.cash / s.value : 1;
    $("pos-" + id).innerHTML = `<table><thead><tr><th>Instrument</th><th>Antal</th><th>Kurs</th><th>Värde</th><th>Vikt</th><th>P/L</th></tr></thead><tbody>${rows}
      <tr><td>KASSA<span class="nm">${esc(c)}</span></td><td></td><td></td><td>${money(s.cash, c)}</td><td>${pct(cw, 1, false)}</td><td></td></tr></tbody></table>
      ${s.planned && s.planned.text ? `<div class="planned"><b>PLANERAT</b> ${esc(s.planned.key || "")}: ${esc(s.planned.text)}<br><span class="muted">${s.market && !s.market.is_open ? `Läggs vid första körningen efter börsöppning ${esc(s.market.open)}.` : "Läggs vid nästa körning."}</span></div>` : ""}`;
    // blotter (newest first; flash new rows)
    const tr = s.trades || [];
    const sk = (seen[id] = seen[id] || new Set());
    $("blr-" + id).textContent = `${tr.length} st`;
    $("blot-" + id).innerHTML = tr.length ? `<table><thead><tr><th>Tid</th><th>Sida</th><th>Instr.</th><th>Antal</th><th>Pris</th><th>Status</th><th>Kostn.</th></tr></thead><tbody>` +
      tr.map((o) => { const k = `${o.id}:${o.status}`, isNew = !firstRender && !sk.has(k); return `<tr class="${isNew ? "newrow" : ""}"><td>${esc(dt(o.filled_at || o.created_at))}</td><td class="side-${esc(o.side)}">${o.side === "BUY" ? "KÖP" : o.side === "SELL" ? "SÄLJ" : esc(o.side)}</td>
        <td>${esc(o.symbol)}</td><td>${num(o.qty, o.qty % 1 ? 8 : 0)}</td><td>${num(o.fill_price ?? o.limit_price)}</td><td><span class="st st-${esc(o.status)}">${esc(o.status)}</span></td><td>${o.commission_sek != null ? money((o.commission_sek || 0) + (o.spread_sek || 0), c) : "–"}</td></tr>`; }).join("") + `</tbody></table>`
      : `<div class="muted" style="padding:12px 0">Inga order ännu.${s.planned && s.planned.text ? " Första ordern ligger planerad – se Positioner." : ""}</div>`;
    tr.forEach((o) => sk.add(`${o.id}:${o.status}`));
    // journal
    $("jr-" + id).innerHTML = (s.journal || []).slice(0, 40).map((j) => `<li><div class="m"><span class="k">${esc(j.kind)}</span>${esc(dt(j.ts))}</div>${esc(j.title)}${j.detail ? `<details><summary>detaljer</summary>${esc(j.detail)}</details>` : ""}</li>`).join("") || "<li class='muted'>Inga händelser ännu.</li>";
    // charts
    candles(id, s); equity(id, s); backtest(id, s);
  }

  function gauge(id, dd, lim) {
    const nolim = lim == null; lim = nolim ? -0.15 : lim;
    const used = Math.min(1, Math.abs(Math.min(0, dd)) / Math.abs(lim || 0.15));
    const ang = Math.PI * (1 - used), r = 50, cx = 60, cy = 60, x = cx + r * Math.cos(ang), y = cy - r * Math.sin(ang);
    const col = used < 0.5 ? "var(--up)" : used < 0.8 ? "var(--am)" : "var(--dn)";
    $("g-" + id).innerHTML = `<svg viewBox="0 0 120 68"><path d="M10 60 A50 50 0 0 1 110 60" fill="none" stroke="#1d2430" stroke-width="9"/>
      <path d="M10 60 A50 50 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)}" fill="none" stroke="${col}" stroke-width="9" ${used === 0 ? 'stroke-opacity="0"' : ""}/>
      <line x1="${cx}" y1="${cy}" x2="${x.toFixed(2)}" y2="${y.toFixed(2)}" stroke="#d7dde8" stroke-width="2"/><circle cx="${cx}" cy="${cy}" r="3" fill="#d7dde8"/></svg>
      <div class="gt"><div>NEDGÅNG FRÅN TOPP</div><div class="big num ${dd < -1e-6 ? "dn" : ""}" style="font-size:20px">${pct(dd, 1)}</div>
      <div>${nolim ? "ingen kill switch (Aktier-boten) · skala −15 %" : `kill switch ${pct(lim, 0)} · ${nf(0).format(used * 100)} % använt`}</div></div>`;
  }

  // ------------------------------------------------------------ charts (lightweight-charts)
  const chartOpts = () => ({ autoSize: true, layout: { background: { type: LW.ColorType.Solid, color: "#0c1016" }, textColor: "#7d889b", fontFamily: getComputedStyle(document.body).getPropertyValue("--mono"), fontSize: 11, attributionLogo: true },
    grid: { vertLines: { color: "#121821" }, horzLines: { color: "#121821" } }, rightPriceScale: { borderColor: "#1d2430" },
    timeScale: { borderColor: "#1d2430", timeVisible: true, secondsVisible: false }, crosshair: { mode: LW.CrosshairMode.Normal },
    localization: { locale: "sv-SE", priceFormatter: (p) => nf(2).format(p) } });
  function bindSeg(id) {
    views[id] = "d";
    $("seg-" + id).querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
      views[id] = b.dataset.v; $("seg-" + id).querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); candles(id, data[id], true);
    }));
  }
  function candles(id, s, refit) {
    if (!LW || !s.ohlc) return;
    const o = s.ohlc, v = views[id] || "d";
    $("chs-" + id).textContent = `${o.symbol} · ${o.name || ""} (${o.ccy || ""})`;
    $("smal-" + id).textContent = o.sma_label || "snitt";
    let c = charts["c" + id];
    if (!c) {
      const ch = LW.createChart($("cc-" + id), chartOpts());
      c = charts["c" + id] = { ch, k: ch.addSeries(LW.CandlestickSeries, { upColor: "#22c55e", downColor: "#ef4444", wickUpColor: "#22c55e", wickDownColor: "#ef4444", borderVisible: false }),
        sma: ch.addSeries(LW.LineSeries, { color: "#ff9f1a", lineWidth: 2, lineType: LW.LineType.WithSteps, priceLineVisible: false, lastValueVisible: true, crosshairMarkerVisible: false }), v: null };
    }
    const intra = v === "i" && (o.intraday_15m || []).length;
    const bars = intra ? o.intraday_15m.map((b) => ({ time: b[0] + TZOFF(), open: b[1], high: b[2], low: b[3], close: b[4] }))
      : (o.daily || []).map((b) => ({ time: ymd(b[0]), open: b[1], high: b[2], low: b[3], close: b[4] }));
    const uniq = []; bars.forEach((b) => { if (!uniq.length || uniq[uniq.length - 1].time !== b.time) uniq.push(b); else uniq[uniq.length - 1] = b; });
    c.k.setData(uniq);
    if (intra) { const lvl = (o.sma || []).slice(-1)[0]; c.sma.setData(lvl ? uniq.map((b) => ({ time: b.time, value: lvl[1] })) : []); }
    else { const first = uniq.length ? uniq[0].time : "0"; c.sma.setData((o.sma || []).filter((p) => p[0] >= first).map((p) => ({ time: p[0], value: p[1] }))); }
    if (v === "i" && !intra) $("chs-" + id).textContent += " – ingen 15-min-data idag (börsen stängd), visar dag";
    if (refit || c.v !== v) { c.ch.timeScale().fitContent(); c.v = v; }
  }
  function lines(key, el, sets, log) {
    let c = charts[key];
    if (!c) {
      const o = chartOpts(); if (log) o.rightPriceScale.mode = LW.PriceScaleMode.Logarithmic;
      const ch = LW.createChart(el, o);
      c = charts[key] = { ch, s: sets.map((x, i) => ch.addSeries(i === 0 ? LW.AreaSeries : LW.LineSeries, i === 0
        ? { lineColor: x.color, topColor: "#22c55e33", bottomColor: "#22c55e00", lineWidth: 2, priceLineVisible: false }
        : { color: x.color, lineWidth: 1, priceLineVisible: false })), fit: false };
    }
    sets.forEach((x, i) => c.s[i].setData(x.data));
    if (!c.fit) { c.ch.timeScale().fitContent(); c.fit = true; }
  }
  const toPts = (arr, intraday) => { const out = []; (arr || []).forEach(([t, v]) => { const time = intraday ? Math.floor(new Date(t).getTime() / 1000) + TZOFF() : String(t).slice(0, 10);
    if (out.length && out[out.length - 1].time >= time) { if (out[out.length - 1].time === time) out[out.length - 1].value = v; return; } out.push({ time, value: v }); }); return out; };
  function equity(id, s) {
    if (!LW) return;
    lines("e" + id, $("ec-" + id), [{ color: "#22c55e", data: toPts(s.equity_curve, true) }, { color: "#94a3b8", data: toPts(s.benchmark_curve, true) }]);
    $("bn-" + id).textContent = s.benchmark_name || "Jämförelse";
    const n = (s.equity_curve || []).length;
    $("en-" + id).textContent = n < 20 ? `Pappershandeln startade ${dt(s.paper_started || (s.equity_curve[0] || [])[0])} – kurvan växer med varje körning.` : "";
  }
  function backtest(id, s) {
    const b = s.backtest_stats || {};
    if (!LW || !(b.curve || []).length) { $("bt-" + id).hidden = !(b.cagr != null); }
    else lines("b" + id, $("btc-" + id), [{ color: "#22c55e", data: toPts(b.curve) }, { color: "#94a3b8", data: toPts(b.benchmark_curve) }], true);
    const bm = b.benchmark || {};
    $("bts-" + id).innerHTML = [["Årlig avk.", pct(b.cagr, 1, false), `index ${pct(bm.cagr, 1, false)}`], ["Max nedgång", pct(b.max_dd, 1), `index ${pct(bm.max_dd, 1)}`],
      ["Sharpe", num(b.sharpe), `index ${num(bm.sharpe)}`], ["Sämsta år", pct(b.worst_year, 1), `${b.worst_year_label || ""} · ${num(b.trades_per_year, 1)} byten/år`]]
      .map(([a, v, n]) => `<div class="stat"><span>${a}</span><b>${v}</b><span>${esc(n)}</span></div>`).join("") + (b.period ? `<div class="muted" style="grid-column:1/-1;font-size:11px">Period ${esc(b.period)}. Historik är ingen garanti.</div>` : "");
  }

  // ------------------------------------------------------------ totals
  // ------------------------------------------------------------ views: TOTALT / RISK / STATUS / LOGG (2026-10-21)
  const sek = (d) => (d.value_sek != null ? d.value_sek : d.currency && d.currency !== "SEK" ? null : d.value);
  const sekDay = (d) => (d.day_change_sek != null ? d.day_change_sek : d.currency && d.currency !== "SEK" ? null : d.day_change);
  const sekStart = (d) => (d.start_value_sek != null ? d.start_value_sek : d.currency && d.currency !== "SEK" ? null : d.start_value);
  const OV = () => data.overview || {};
  const RK = () => OV().risk || {};
  function bars(obj, lim, n) {
    const e = Object.entries(obj || {}).filter(([, v]) => v != null && Math.abs(v) >= 0.05).slice(0, n || 10);
    if (!e.length) return `<div class="muted">Ingen data.</div>`;
    const mx = Math.max(...e.map(([, v]) => Math.abs(v)), lim || 0);
    return e.map(([k, v]) => `<div class="bx${lim && v > lim ? " over" : ""}"><span class="k">${esc(k)}</span><span class="t"><i style="width:${Math.max(1, (Math.abs(v) / mx) * 100).toFixed(1)}%"></i>${lim ? `<u style="left:${((lim / mx) * 100).toFixed(1)}%"></u>` : ""}</span><b>${nf(1).format(v)} %</b></div>`).join("");
  }
  const lvl = (l) => `<span class="lvl ${l === "HÖG" ? "hi" : l === "MEDEL" ? "md" : "in"}">${esc(l || "INFO")}</span>`;
  function sleeveState(s) {
    const why = [];
    if (!s) return { c: "FEL", why: ["ingen data publicerad"] };
    let c = "OK";
    if (s.halted) { c = "FEL"; why.push("stopp aktivt"); }
    if (s.error) { c = "FEL"; why.push(String(s.error)); }
    const vm = mins(s.updated_at || s.heartbeat_at);
    if (vm > 120) { if (c === "OK") c = "VARNING"; why.push(`värdering ${ago(s.updated_at)}`); }
    if (s.source_asof && mins(s.source_asof) > 30 * 60) { if (c === "OK") c = "VARNING"; why.push(`källdata ${ago(s.source_asof)}`); }
    if ((s.data_stale || []).length) { if (c === "OK") c = "VARNING"; why.push("kurs saknas: " + s.data_stale.join(", ")); }
    return { c, why };
  }
  const stb = (c) => `<span class="stb ${c === "OK" ? "ok" : c === "VARNING" ? "wa" : "er"}">${c}</span>`;

  function renderTotal() {
    const pane = $("pane-total"), list = SLEEVES.filter((s) => data[s.id]), r = RK();
    let val = 0, day = 0, start = 0;
    list.forEach((s) => { const d = data[s.id]; val += sek(d) || 0; day += sekDay(d) || 0; start += sekStart(d) || 0; });
    const trs = SLEEVES.map((s) => { const d = data[s.id]; if (!d) return `<tr><td>${s.name}</td><td class="muted" colspan="7">ingen data</td></tr>`;
      const g = d.gate || gateFallback(d), v = sek(d);
      return `<tr><td>${s.name}<span class="nm">${esc(d.title || "")}</span></td><td>${money(v)}${d.currency && d.currency !== "SEK" ? `<span class="nm">${money(d.value, d.currency, 2)}</span>` : ""}</td><td>${pct(val ? v / val : null, 1, false)}</td>
        <td class="${ud(d.day_change_pct)}">${pct(d.day_change_pct)}</td><td class="${ud(d.total_change_pct)}">${pct(d.total_change_pct)}</td><td class="${d.drawdown_pct < -1e-6 ? "dn" : ""}">${pct(d.drawdown_pct, 1)}</td>
        <td class="${g.passed === g.total ? "up" : "dn"}">${g.passed}/${g.total}</td><td class="muted">${esc(ago(d.updated_at))}</td></tr>`; }).join("");
    const tn = (r.top_names || []).map((t) => `<tr><td>${esc(t.key)}<span class="nm">${esc(t.name || "")}</span></td><td class="${t.pct > ((r.limits || {}).single_name_pct || 10) ? "dn" : ""}">${nf(1).format(t.pct)} %</td><td>${money(t.value_sek)}</td>
      <td class="via">${Object.entries(t.via || {}).map(([k, v]) => `<span class="chip">${esc(k.replace(":direkt", " (direkt)"))} ${money(v)}</span>`).join(" ")}</td></tr>`).join("");
    const L = r.limits || {};
    pane.innerHTML = `<div class="grid">
      ${P("tot", "s5", "Totalt – alla delar (SEK)", `${list.length} av ${SLEEVES.length} delar`, `<div class="big num">${money(val)}</div>
        <div class="kv"><span>P/L idag</span><b class="${ud(day)}">${day > 0 ? "+" : ""}${money(day)} · ${pct(val - day ? day / (val - day) : 0)}</b>
        <span>Totalt sedan start</span><b class="${ud(val - start)}">${pct(start ? val / start - 1 : 0)} <span class="muted">(start ${money(start)})</span></b>
        <span>Samlad nedgång (riskmgr)</span><b class="${(r.aggregate_drawdown_pct || 0) < 0 ? "dn" : ""}">${r.aggregate_drawdown_pct != null ? nf(1).format(r.aggregate_drawdown_pct) + " %" : "–"}</b>
        <span>Riskmgr NAV</span><b>${money(r.total_nav_sek)} <span class="muted">${esc(dt(r.generated_at))}</span></b>
        <span>USD-andel</span><b class="${r.usd_pct > (L.usd_pct || 50) ? "am" : ""}">${r.usd_pct != null ? nf(1).format(r.usd_pct) + " %" : "–"}</b>
        <span>Icke-SEK</span><b class="${r.non_sek_pct > (L.non_sek_pct || 65) ? "am" : ""}">${r.non_sek_pct != null ? nf(1).format(r.non_sek_pct) + " %" : "–"}</b>
        <span>USD/SEK</span><b>${num(r.usdsek, 4)}</b></div>
        <div class="muted" style="font-size:11px;margin-top:6px">Omfattning: ${esc(r.scope || "–")}. Delar i USD räknas om med USD/SEK (Yahoo, fördröjd).</div>`)}
      ${P("totv", "s7", "Delar", "värde i SEK", `<div class="tw"><table><thead><tr><th>Del</th><th>Värde</th><th>Andel</th><th>Idag</th><th>Totalt</th><th>Nedgång</th><th>Live-spärr</th><th>Värderad</th></tr></thead><tbody>${trs}</tbody></table></div>
        <div class="muted" style="font-size:11px;margin-top:6px">${esc(STRUKEN)}</div>`)}
      ${P("tcur", "s4", "Valutaexponering", `gräns USD ${L.usd_pct || 50} %`, bars(r.by_currency_pct, null, 8))}
      ${P("tsec", "s4", "Sektor (look-through)", `gräns ${L.sector_pct || 35} %`, bars(r.by_sector_pct, L.sector_pct, 10))}
      ${P("tcty", "s4", "Land (look-through)", "", bars(r.by_country_pct, null, 8))}
      ${P("tlt", "s12", "Största exponeringar – look-through över alla delar", `gräns per namn ${L.single_name_pct || 10} %`, `<div class="tw"><table><thead><tr><th>Namn</th><th>Andel</th><th>Värde</th><th>Via</th></tr></thead><tbody>${tn || `<tr><td colspan="4" class="muted">Ingen riskdata.</td></tr>`}</tbody></table></div>
        <div class="muted" style="font-size:11px;margin-top:6px">${esc((r.notes || []).join(" "))}</div>`)}
    </div>`;
  }

  function renderRisk() {
    const pane = $("pane-risk"), r = RK(), today = new Date().toLocaleDateString("sv-SE");
    const fl = r.flags || [], hi = fl.filter((f) => f.level === "HÖG").length;
    $("tabsub-risk").innerHTML = hi ? `<span class="dn">${hi} HÖG</span>` : fl.length ? `<span class="am">${fl.length}</span>` : "";
    const ev = (r.events_all || r.upcoming_events || []).slice().sort((a, b) => (a.date + (a.time || "")).localeCompare(b.date + (b.time || "")));
    pane.innerHTML = `<div class="grid">
      ${P("rfl", "s6", "Riskflaggor (rådgivande)", `${fl.length} st · ${esc(dt(r.generated_at))}`, fl.length ? `<div class="fl">${fl.map((f) => `<div class="fr">${lvl(f.level)}<div><b>${esc(f.code || "")}</b><div>${esc(f.text)}</div></div></div>`).join("")}</div>` : `<div class="muted">Inga flaggor.</div>`)}
      ${P("rev", "s6", "Händelsekalender", "rapporter, FOMC", `<div class="tw"><table><thead><tr><th>Datum</th><th>Tid</th><th>Händelse</th><th>Berör</th><th>Exponering</th></tr></thead><tbody>${ev.map((e) => `<tr class="${e.date < today ? "past" : e.date === today ? "today" : ""}"><td>${esc(e.date)}</td><td>${esc(e.time || "")}</td><td>${esc(e.text)}</td><td>${esc((e.keys || []).join(", "))}</td><td class="${e.exposure_pct >= ((r.limits || {}).event_exposure_pct || 3) ? "am" : ""}">${e.exposure_pct != null ? nf(1).format(e.exposure_pct) + " %" : "–"}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">Inga händelser.</td></tr>`}</tbody></table></div>
        <div class="muted" style="font-size:11px;margin-top:6px">Källor: ${esc([...new Set(ev.map((e) => e.source).filter(Boolean))].join(" · "))}</div>`)}
      ${P("rsl", "s6", "Delar mot kill switch", "", `<div class="tw"><table><thead><tr><th>Del</th><th>NAV (SEK)</th><th>Andel</th><th>Nedgång</th><th>Kill switch</th></tr></thead><tbody>${(r.sleeves || []).map((x) => `<tr><td>${esc(x.name || x.id)}</td><td>${money(x.nav)}</td><td>${x.weight_pct != null ? nf(1).format(x.weight_pct) + " %" : "–"}</td><td class="${x.dd < 0 ? "dn" : ""}">${pct(x.dd, 1)}</td><td>${x.kill != null ? pct(x.kill, 0) : "ingen"}</td></tr>`).join("")}</tbody></table></div>`)}
      ${P("rlim", "s6", "Gränser och källor", esc(r.mode || ""), `<div class="kv">${Object.entries(r.limits || {}).map(([k, v]) => `<span>${esc(k)}</span><b>${esc(v)}</b>`).join("")}</div>
        <div class="src">${Object.entries(r.sources || {}).map(([k, v]) => `<div><b>${esc(k)}</b> ${esc(v)}</div>`).join("")}</div>`)}
    </div>`;
  }

  function renderStatus() {
    const pane = $("pane-status"), o = OV(), r = RK(), ib = o.inbox || {};
    const rows = SLEEVES.map((s) => { const d = data[s.id], st = sleeveState(d), g = d ? d.gate || gateFallback(d) : null, ne = d && d.signal && d.signal.next_eval_at;
      return `<tr><td>${s.name}</td><td>${stb(st.c)}</td><td>${d ? esc(ago(d.updated_at)) : "–"}</td><td>${d && d.source_asof ? esc(ago(d.source_asof)) : d ? "egen motor" : "–"}</td>
        <td class="${g && g.passed === g.total ? "up" : "dn"}"><b>${g ? `${g.passed} av ${g.total}` : "–"}</b></td><td>${ne ? esc(dt(ne)) + ` <span class="muted">${esc(until(ne))}</span>` : "–"}</td><td class="muted">${esc(st.why.join("; ") || "")}</td></tr>`; }).join("");
    const nOk = SLEEVES.filter((s) => sleeveState(data[s.id]).c === "OK").length;
    $("tabsub-status").innerHTML = `<span class="${nOk === SLEEVES.length ? "up" : "am"}">${nOk}/${SLEEVES.length}</span>`;
    const svc = [];
    Object.entries(o.health || {}).forEach(([k, v]) => svc.push([k, v && v.code === 200 ? "OK" : "FEL", v ? `HTTP ${v.code ?? "–"}` : "–"]));
    Object.entries(o.launchd || {}).forEach(([k, v]) => svc.push([k.replace("com.hermes.", ""), v.last_exit === "0" || v.pid ? "OK" : "VARNING", `${v.pid ? "kör (pid " + v.pid + ")" : "väntar"} · senaste exit ${v.last_exit}`]));
    const rAge = mins(r.generated_at);
    svc.push(["riskhanterare", rAge <= 120 && /Aktier/.test(r.scope || "") ? "OK" : rAge <= 120 ? "VARNING" : "FEL", `${r.scope || "–"} · körd ${ago(r.generated_at)}`]);
    svc.push(["brevlåda box→Mac", ib.ok && mins(ib.box_generated_at) <= 30 * 60 ? "OK" : ib.ok ? "VARNING" : "FEL", `boxen skrev ${ago(ib.box_generated_at)} · kollad ${ago(ib.checked_at)}${ib.error ? " · " + ib.error : ""}`]);
    svc.push(["swing / intraday", "STRUKEN", STRUKEN]);
    pane.innerHTML = `<div class="grid">
      ${P("sts", "s12", "Status per del", `${nOk} av ${SLEEVES.length} OK · värdering äldre än 2 h eller källdata äldre än 30 h = VARNING`, `<div class="tw"><table><thead><tr><th>Del</th><th>Status</th><th>Värderad</th><th>Källdata</th><th>Go-live</th><th>Nästa beslut</th><th>Anmärkning</th></tr></thead><tbody>${rows}</tbody></table></div>
        <div class="muted" style="font-size:11px;margin-top:6px">Go-live kräver 5 av 5 krav (bl.a. 90 dagar på papper). Allt är rött tills dess. Inget går live utan Onedins beslut.</div>`)}
      ${P("svc", "s12", "Tjänster på Mac:en", `${esc(dt(o.generated_at))}`, `<div class="tw"><table><thead><tr><th>Tjänst</th><th>Status</th><th>Detalj</th></tr></thead><tbody>${svc.map(([a, b, c]) => `<tr><td>${esc(a)}</td><td>${b === "STRUKEN" ? `<span class="stb mu">STRUKEN</span>` : stb(b)}</td><td class="muted">${esc(c)}</td></tr>`).join("")}</tbody></table></div>`)}
    </div>`;
  }

  function renderLog() {
    const pane = $("pane-logg"), o = OV();
    const t = Array.isArray(o.tasks) ? o.tasks : (o.tasks && o.tasks.tasks) || [];
    const dec = o.decisions || [];
    pane.innerHTML = `<div class="grid">
      ${P("lgd", "s7", "Beslutslogg", "senaste först", dec.length ? `<ol class="jr dl">${dec.map((d) => `<li><div class="m">${esc(d.rubrik)}</div>${(d.rader || []).length ? `<ul>${d.rader.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}</li>`).join("")}</ol>` : `<div class="muted">Ingen beslutslogg ännu.</div>`)}
      ${P("lgt", "s5", "Uppgifter", `${t.filter((x) => x.status !== "Done").length} öppna`, `<div class="tw"><table><thead><tr><th>Id</th><th>Uppgift</th><th>Ägare</th><th>Status</th></tr></thead><tbody>${t.map((x) => `<tr><td>${esc(x.id)}</td><td style="white-space:normal">${esc(x.task)}</td><td>${esc(x.owner || "")}</td><td><span class="st st-${x.status === "Done" ? "FILLED" : x.status === "Blocked" ? "REJECTED" : "OPEN"}">${esc(x.status)}</span></td></tr>`).join("")}</tbody></table></div>
        <div class="planned">${esc(STRUKEN)}</div>`)}
    </div>`;
  }

  // ------------------------------------------------------------ render all
  function render(d) {
    data = d;
    SLEEVES.forEach((s) => {
      if (d[s.id]) { try { renderSleeve(s.id, d[s.id]); } catch (e) { console.error("render " + s.id + ": " + (e && e.message)); } }
      else { const p = $("pane-" + s.id); if (!p.dataset.soon) { p.innerHTML = soonPane(s.id, s.name); p.dataset.soon = "1"; } $("tabsub-" + s.id).textContent = "snart"; }
    });
    [renderTotal, renderRisk, renderStatus, renderLog, tape, statusBar].forEach((f) => { try { f(); } catch (e) { console.error("render " + f.name + ": " + (e && e.message)); } });
    const g = SLEEVES.map((s) => d[s.id] && d[s.id].generated_at).filter(Boolean).sort().pop();
    $("foot-gen").textContent = `Ögonblicksbild ${dt(g)} · hämtar ny data varje minut`;
    firstRender = false;
  }

  // ------------------------------------------------------------ boot
  (async () => {
    const saved = await loadKey();
    if (!saved) return showLock();
    try { keySalt = saved.salt; key = saved.key; start(await fetchAll(key)); }
    catch (e) { if (e && e.name === "OperationError") forget(); showLock(e && e.name === "OperationError" ? "Logga in igen." : "Kunde inte hämta data – försök igen."); }
  })();
})();
