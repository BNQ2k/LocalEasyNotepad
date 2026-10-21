/* LocalEasyNotepad
 * Offline notes stored in this browser's localStorage. Nothing is ever sent anywhere.
 * Encryption: Web Crypto API, AES-256-GCM with PBKDF2-SHA256 derived keys.
 */
(() => {
'use strict';

/* ---------- Constants and small helpers ---------- */
const KEY = 'localeasynotepad.data';
const THEME_KEY = 'localeasynotepad.theme';
const ITERATIONS = 250000;
const STORAGE_LIMIT = 5e6;          // roughly what browsers allow for localStorage (characters)
const TRASH_DAYS = 30;
const MAX_FILE = 3e6;               // bytes per attachment
const COLORS = ['red', 'orange', 'yellow', 'green', 'blue', 'purple', 'pink'];
const NS = 'http://www.w3.org/2000/svg';
const TAG_RE = /(?:^|\s)#([\p{L}\p{N}_-]{1,40})/gu;

const $ = (s, r = document) => r.querySelector(s);
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const ts = () => Date.now();
const fmt = t => new Date(t).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
const fmtDay = t => new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
const fmtSize = b => b < 1024 ? b + ' B' : b < 1048576 ? Math.round(b / 1024) + ' KB' : (b / 1048576).toFixed(1) + ' MB';
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

// Builds DOM safely (text is never parsed as HTML).
function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value') e.value = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  kids.flat(9).forEach(c => c != null && c !== false && e.append(c));
  return e;
}

const ICONS = {
  plus: 'M12 5v14M5 12h14', pin: 'M12 17v5M9 3h6l-1 7 4 4H6l4-4z',
  lock: 'M6 11h12v10H6zM8 11V7a4 4 0 018 0v4', unlock: 'M6 11h12v10H6zM8 11V7a4 4 0 017.5-2',
  copy: 'M9 9h11v11H9zM5 15V4h11', print: 'M7 9V3h10v6M6 18H4v-8h16v8h-2M7 14h10v7H7z',
  clip: 'M20 11l-8.5 8.5a5 5 0 01-7-7L13 4a3.5 3.5 0 015 5l-8.5 8.5a2 2 0 01-3-3L14 7',
  trash: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13', restore: 'M3 12a9 9 0 109-9M3 4v5h5',
  clock: 'M12 3a9 9 0 100 18 9 9 0 000-18zM12 7v5l3 2',
  sun: 'M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5',
  moon: 'M20 14A8 8 0 1110 4a6.5 6.5 0 0010 10z', shield: 'M12 3l8 3v6c0 5-4 8-8 9-4-1-8-4-8-9V6z',
  back: 'M15 5l-7 7 7 7', menu: 'M4 6h16M4 12h16M4 18h16', download: 'M12 4v12M7 11l5 5 5-5M5 20h14',
  x: 'M6 6l12 12M18 6L6 18', edit: 'M4 20h4L19 9l-4-4L4 16z', note: 'M6 3h9l4 4v14H6zM14 3v5h5', file: 'M6 3h9l4 4v14H6z'
};
function ico(name) {
  const s = document.createElementNS(NS, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('class', 'ico');
  const p = document.createElementNS(NS, 'path');
  p.setAttribute('d', ICONS[name]);
  s.append(p);
  return s;
}

/* ---------- Cryptography ---------- */
const enc = new TextEncoder(), dec = new TextDecoder();
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const b64 = u8 => {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
};
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// Turns a PIN, password or passphrase into an AES-256 key.
async function derive(secret, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
// A fresh random IV is used for every encryption.
async function seal(key, obj) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}
async function unseal(key, p) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(p.iv) }, key, unb64(p.ct));
  return JSON.parse(dec.decode(pt));
}

/* ---------- State ---------- */
let db = { notes: [], folders: [] };
// Note shape: { id, color, folderId, pinned, trashed, trashedAt, expiresAt, created, updated, locked, blob, c }
// c = { title, body, tags[], files[] }. For a locked note c is null until unlocked, and blob holds the ciphertext.
let vault = null;                   // { key, salt } when whole-app encryption is on
const noteKeys = new Map();         // note id -> { key, salt } while a locked note is open
const ui = { view: 'all', q: '', sel: null };
let saveTimer = null, rev = 0, dirty = false, frozen = false, chain = Promise.resolve();

const get = id => db.notes.find(n => n.id === id);
const cur = () => get(ui.sel);

/* ---------- Saving ---------- */
async function sealNote(n) {
  const k = noteKeys.get(n.id);
  if (k && n.c) n.blob = { s: k.salt, ...(await seal(k.key, n.c)) };
}
async function persist() {
  if (frozen) return;
  const notes = [];
  for (const n of db.notes) {
    if (n.locked) { await sealNote(n); const { c, ...rest } = n; notes.push(rest); }   // plain text never stored
    else notes.push(n);
  }
  const data = { v: 1, notes, folders: db.folders };
  const out = vault ? { v: 1, enc: 1, s: vault.salt, ...(await seal(vault.key, data)) } : data;
  localStorage.setItem(KEY, JSON.stringify(out));
}
function saveNow() {
  clearTimeout(saveTimer);
  const r = rev;
  chain = chain.then(async () => {
    try {
      await persist();
      if (r === rev) dirty = false;
      setStatus('Saved');
      meter();
      return true;
    } catch (e) {
      setStatus('Not saved');
      toast(e && e.name === 'QuotaExceededError' ? 'Storage is full. Remove attachments or export a backup.' : 'Could not save: ' + (e && e.message));
      return false;
    }
  });
  return chain;
}
function scheduleSave() { rev++; dirty = true; setStatus('Saving…'); clearTimeout(saveTimer); saveTimer = setTimeout(saveNow, 400); }
function touch(n) { n.updated = ts(); scheduleSave(); }      // content changed
function setStatus(t) { const s = $('#status'); if (s) s.textContent = t; }
function meter() {
  const used = (localStorage.getItem(KEY) || '').length;
  const pct = Math.min(100, Math.round(used / STORAGE_LIMIT * 100));
  $('#meter').value = pct;
  $('#meterTxt').textContent = `Storage used: about ${pct}% (${(used / 1e6).toFixed(1)} MB)`;
}

/* ---------- Dialogs and toasts ---------- */
// Generic dialog. Resolves with the field values (or action result), or null if cancelled.
function ask(o) {
  return new Promise(resolve => {
    const d = $('#dlg'), f = $('#dlgForm');
    const inputs = (o.fields || []).map(x => el('input', { type: x.type || 'password', value: x.value || '', autocomplete: 'off', 'aria-label': x.label }));
    const err = el('p', { class: 'err' });
    const okB = el('button', { class: 'primary', type: 'submit' }, o.ok || 'OK');
    const done = v => { d.close(); resolve(v); };
    const btns = el('div', { class: 'row end' });
    if (o.extra) btns.append(el('button', { type: 'button', class: 'danger', onclick: () => done({ extra: true }) }, o.extra.label));
    if (o.cancel !== false) btns.append(el('button', { type: 'button', onclick: () => done(null) }, 'Cancel'));
    btns.append(okB);
    f.replaceChildren(el('div', {},
      el('h3', {}, o.title),
      o.text ? el('p', { class: 'muted' }, o.text) : null,
      (o.fields || []).map((x, i) => el('label', {}, x.label, inputs[i])),
      err, btns));
    f.onsubmit = async e => {
      e.preventDefault();
      okB.disabled = true; err.textContent = '';
      try { done(o.action ? await o.action(inputs.map(i => i.value)) : inputs.map(i => i.value)); }
      catch (x) { err.textContent = x.message; okB.disabled = false; }
    };
    d.oncancel = e => { if (o.cancel === false) e.preventDefault(); else done(null); };
    d.showModal();
    if (inputs[0]) inputs[0].focus();
  });
}
const yes = async (title, text, ok) => !!(await ask({ title, text, ok }));

let toastTimer;
function toast(msg, label, fn) {
  const t = $('#toast');
  t.replaceChildren(msg, label ? el('button', { class: 'plain', onclick: () => { fn(); t.classList.remove('show'); } }, label) : '');
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), label ? 6000 : 3500);
}

/* ---------- Note helpers ---------- */
function tagsOf(n) {
  if (!n.c) return [];
  const s = new Set(n.c.tags);
  for (const m of n.c.body.matchAll(TAG_RE)) s.add(m[1].toLowerCase());
  return [...s];
}
function titleOf(n) {
  if (n.locked && !n.c) return 'Locked note';
  return n.c.title.trim() || n.c.body.trim().split('\n')[0].slice(0, 60) || 'Untitled';
}
const isEmpty = n => !n.locked && !n.c.title.trim() && !n.c.body.trim() && !n.c.files.length;
const folderName = id => (db.folders.find(f => f.id === id) || {}).name;

function visible() {
  const q = ui.q.trim().toLowerCase(), v = ui.view;
  return db.notes.filter(n => {
    if (v === 'trash') { if (!n.trashed) return false; }
    else {
      if (n.trashed) return false;
      if (v === 'pin' && !n.pinned) return false;
      if (v.startsWith('f:') && n.folderId !== v.slice(2)) return false;
      if (v.startsWith('t:') && !tagsOf(n).includes(v.slice(2))) return false;
    }
    if (q) {
      if (!n.c) return false;                                  // locked notes are not searchable
      const hay = (n.c.title + ' ' + n.c.body + ' ' + tagsOf(n).join(' ') + ' ' + n.c.files.map(f => f.name).join(' ')).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }).sort((a, b) => (v === 'trash' ? 0 : (+!!b.pinned) - (+!!a.pinned)) || b.updated - a.updated);
}
function viewTitle() {
  const v = ui.view;
  if (v === 'all') return 'All notes';
  if (v === 'pin') return 'Pinned';
  if (v === 'trash') return 'Trash';
  if (v.startsWith('f:')) return folderName(v.slice(2)) || 'Folder';
  return '#' + v.slice(2);
}

/* ---------- Rendering: sidebar ---------- */
function dropZone(node, folderId) {
  node.addEventListener('dragover', e => { e.preventDefault(); node.classList.add('over'); });
  node.addEventListener('dragleave', () => node.classList.remove('over'));
  node.addEventListener('drop', e => {
    e.preventDefault(); node.classList.remove('over');
    const n = get(e.dataTransfer.getData('text/plain'));
    if (n && !n.trashed) { n.folderId = folderId; scheduleSave(); renderAll(); toast(folderId ? `Moved to “${folderName(folderId)}”` : 'Removed from folder'); }
  });
}
function navItem(id, icon, label, count, canDrop) {
  const b = el('button', { class: 'nav' + (ui.view === id ? ' on' : ''), onclick: () => setView(id) },
    ico(icon), el('span', { class: 'lbl' }, label), el('span', { class: 'cnt' }, count));
  if (canDrop) dropZone(b, null);
  return b;
}
function renderSide() {
  const live = db.notes.filter(n => !n.trashed);
  $('#views').replaceChildren(
    navItem('all', 'note', 'All notes', live.length, true),
    navItem('pin', 'pin', 'Pinned', live.filter(n => n.pinned).length),
    navItem('trash', 'trash', 'Trash', db.notes.length - live.length));

  const fl = $('#folders');
  fl.replaceChildren(...db.folders.map(f => {
    const id = 'f:' + f.id;
    const row = el('div', { class: 'nav' + (ui.view === id ? ' on' : '') },
      el('button', { class: 'dot' + (f.color ? ' c-' + f.color : ''), title: 'Change folder color', 'aria-label': 'Change folder color', onclick: () => {
        const order = ['', ...COLORS];
        f.color = order[(order.indexOf(f.color || '') + 1) % order.length];
        scheduleSave(); renderSide();
      } }),
      el('button', { class: 'plain lbl', onclick: () => setView(id) }, f.name),
      el('span', { class: 'cnt' }, live.filter(n => n.folderId === f.id).length),
      el('button', { class: 'ib act', title: 'Rename folder', 'aria-label': 'Rename folder', onclick: () => renameFolder(f) }, ico('edit')),
      el('button', { class: 'ib act', title: 'Delete folder', 'aria-label': 'Delete folder', onclick: () => deleteFolder(f) }, ico('x')));
    dropZone(row, f.id);
    return row;
  }));
  if (!db.folders.length) fl.append(el('p', { class: 'muted small pad0' }, 'Create a folder, then drag notes onto it.'));

  const counts = new Map();
  live.forEach(n => tagsOf(n).forEach(t => counts.set(t, (counts.get(t) || 0) + 1)));
  const tg = $('#tags');
  tg.replaceChildren(...[...counts].sort((a, b) => a[0].localeCompare(b[0])).map(([t, c]) =>
    el('button', { class: 'tagbtn' + (ui.view === 't:' + t ? ' on' : ''), onclick: () => setView(ui.view === 't:' + t ? 'all' : 't:' + t) }, `#${t} ${c}`)));
  if (!counts.size) tg.append(el('span', { class: 'muted small' }, 'Type #word in a note to tag it.'));
}

/* ---------- Rendering: list ---------- */
function noteRow(n) {
  const open = !n.locked || n.c;
  const meta = [el('span', {}, fmtDay(n.updated))];
  if (n.pinned) meta.push(ico('pin'));
  if (n.locked) meta.push(ico('lock'));
  if (open && n.c.files.length) meta.push(ico('clip'));
  if (n.expiresAt && !n.trashed) meta.push(ico('clock'));
  if (n.folderId && folderName(n.folderId)) meta.push(el('span', {}, '· ' + folderName(n.folderId)));
  tagsOf(n).slice(0, 3).forEach(t => meta.push(el('span', {}, '#' + t)));
  const snippet = n.locked && !n.c ? 'Enter your PIN or password to read' : n.c.body.replace(/\s+/g, ' ').trim().slice(0, 100);
  return el('div', {
    class: 'note' + (n.color ? ' c-' + n.color : '') + (n.id === ui.sel ? ' sel' : ''),
    draggable: n.trashed ? null : 'true', tabindex: '0', role: 'button',
    onclick: () => select(n.id),
    onkeydown: e => { if (e.key === 'Enter') select(n.id); },
    ondragstart: e => { e.dataTransfer.setData('text/plain', n.id); e.dataTransfer.effectAllowed = 'move'; }
  }, el('div', { class: 't' }, titleOf(n)), el('div', { class: 's' }, snippet || '\u00a0'), el('div', { class: 'm' }, meta));
}
function renderList() {
  const items = visible();
  $('#listTitle').textContent = viewTitle();
  $('#emptyTrash').hidden = !(ui.view === 'trash' && items.length);
  const list = $('#list');
  list.replaceChildren(...items.map(noteRow));
  if (!items.length) list.append(el('p', { class: 'muted pad' }, ui.q ? 'No notes match your search.' : ui.view === 'trash' ? 'The trash is empty.' : 'No notes here yet.'));
}

/* ---------- Rendering: editor ---------- */
const show = (sel, on) => { $(sel).hidden = !on; };

function renderNote() {
  const n = cur();
  $('#empty').hidden = !!n;
  $('#noteView').hidden = !n;
  if (!n) { $('#app').classList.remove('editing'); return; }
  const open = !n.locked || !!n.c, tr = n.trashed;

  show('#lockScreen', !open); show('#content', open);
  show('#pinBtn', !tr); show('#swatches', !tr); show('#folderSel', !tr);
  show('#expBtn', open && !tr); show('#lockBtn', open && !tr); show('#unlockRemoveBtn', open && !tr && n.locked);
  show('#dupBtn', open && !tr); show('#printBtn', open); show('#attachBtn', open && !tr);
  show('#trashBtn', !tr); show('#restoreBtn', tr); show('#purgeBtn', tr);

  $('#pinBtn').classList.toggle('on', !!n.pinned);
  $('#lockBtn').title = n.locked ? 'Lock now' : 'Lock with PIN or password';
  const sw = $('#swatches');
  sw.replaceChildren(...['', ...COLORS].map(c => el('button', {
    class: 'sw' + (c ? ' c-' + c : ''), type: 'button', title: c ? 'Color: ' + c : 'No color', 'aria-label': c ? 'Color ' + c : 'No color',
    'aria-pressed': String(n.color === c),
    onclick: () => { n.color = c; scheduleSave(); renderNote(); renderList(); }
  })));
  const fs = $('#folderSel');
  fs.replaceChildren(el('option', { value: '' }, 'No folder'), ...db.folders.map(f => el('option', { value: f.id }, f.name)));
  fs.value = n.folderId || '';

  const b = $('#banner');
  if (tr) { b.hidden = false; b.textContent = `This note is in the trash and will be deleted automatically after ${TRASH_DAYS} days.`; }
  else if (n.expiresAt) { b.hidden = false; b.textContent = `This note expires on ${fmt(n.expiresAt)} and will then move to the trash.`; }
  else b.hidden = true;

  if (!open) { $('#unlockErr').textContent = ''; $('#unlockPw').value = ''; return; }
  $('#title').value = n.c.title; $('#title').readOnly = tr;
  $('#body').value = n.c.body; $('#body').readOnly = tr;
  $('#tagIn').hidden = tr;
  renderTags(n); renderFiles(n); renderMeta(n);
}
function renderMeta(n) {
  const words = n.c.body.trim() ? n.c.body.trim().split(/\s+/).length : 0;
  $('#meta').textContent = `${words} word${words === 1 ? '' : 's'} · edited ${fmt(n.updated)}`;
}
function renderTags(n) {
  const manual = n.c.tags, auto = tagsOf(n).filter(t => !manual.includes(t));
  $('#tagChips').replaceChildren(
    ...manual.map(t => el('span', { class: 'chip' }, '#' + t, n.trashed ? null : el('button', { title: 'Remove tag', 'aria-label': 'Remove tag ' + t, onclick: () => {
      n.c.tags = n.c.tags.filter(x => x !== t); touch(n); renderTags(n); renderSide(); renderList();
    } }, '×'))),
    ...auto.map(t => el('span', { class: 'chip auto', title: 'From #hashtag in the text' }, '#' + t)));
}
function addTag(n, raw) {
  const t = raw.replace(/^#+/, '').toLowerCase().replace(/[^\p{L}\p{N}_-]/gu, '').slice(0, 40);
  if (!t || n.c.tags.includes(t)) return;
  n.c.tags.push(t); touch(n); renderTags(n); renderSide(); renderList();
}
function renderFiles(n) {
  $('#files').replaceChildren(...n.c.files.map(f => el('div', { class: 'file' },
    f.type.startsWith('image/') ? el('img', { src: f.data, alt: '' }) : el('span', { class: 'fi' }, ico('file')),
    el('span', { class: 'nm', title: f.name }, f.name), el('span', { class: 'muted small' }, fmtSize(f.size)),
    el('button', { class: 'ib', title: 'Download', 'aria-label': 'Download ' + f.name, onclick: async () => saveBlob(await (await fetch(f.data)).blob(), f.name) }, ico('download')),
    n.trashed ? null : el('button', { class: 'ib', title: 'Remove attachment', 'aria-label': 'Remove ' + f.name, onclick: () => {
      n.c.files = n.c.files.filter(x => x.id !== f.id); touch(n); renderFiles(n); renderList(); meterSoon();
    } }, ico('x')))));
}
function saveBlob(blob, name) {
  const a = el('a', { href: URL.createObjectURL(blob), download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}
function renderAll() { renderSide(); renderList(); renderNote(); }
const refresh = debounce(() => { renderSide(); renderList(); }, 250);
const meterSoon = debounce(() => saveNow(), 500);

/* ---------- Navigation and note actions ---------- */
function setView(v) {
  ui.view = v;
  $('#app').classList.remove('menu');
  const n = cur();
  if (n && !visible().includes(n)) ui.sel = null;
  renderAll();
}
function select(id) {
  const prev = cur();
  if (prev && prev.id !== id && isEmpty(prev)) { db.notes = db.notes.filter(x => x !== prev); scheduleSave(); renderSide(); }
  ui.sel = id;
  $('#app').classList.add('editing');
  renderList(); renderNote();
  const n = cur();
  if (n && n.locked && !n.c) $('#unlockPw').focus();
}
function newNote() {
  if (ui.view === 'trash') ui.view = 'all';
  ui.q = ''; $('#search').value = '';
  const t = ts(), v = ui.view;
  const n = {
    id: uid(), color: '', pinned: v === 'pin', trashed: false, created: t, updated: t, expiresAt: null, locked: false,
    folderId: v.startsWith('f:') ? v.slice(2) : null,
    c: { title: '', body: '', tags: v.startsWith('t:') ? [v.slice(2)] : [], files: [] }
  };
  db.notes.push(n);
  select(n.id);
  renderSide();
  $('#title').focus();
}
function duplicateNote(n) {
  const t = ts();
  const copy = { ...n, id: uid(), pinned: false, created: t, updated: t, c: structuredClone(n.c) };
  delete copy.blob;
  copy.c.title = (n.c.title.trim() || titleOf(n)) + ' (copy)';
  if (n.locked) noteKeys.set(copy.id, noteKeys.get(n.id));      // the copy stays locked with the same PIN or password
  db.notes.push(copy);
  scheduleSave(); select(copy.id); renderSide();
  toast('Note duplicated');
}
function trashNote(n) {
  n.trashed = true; n.trashedAt = ts();
  scheduleSave(); ui.sel = null; renderAll();
  toast('Moved to trash', 'Undo', () => restoreNote(n, true));
}
function restoreNote(n, keepSel) {
  n.trashed = false; delete n.trashedAt; n.expiresAt = null;
  if (n.folderId && !folderName(n.folderId)) n.folderId = null;
  scheduleSave();
  if (keepSel) { ui.view = 'all'; ui.sel = n.id; }
  renderAll();
}
async function purgeNote(n) {
  if (!await yes('Delete forever?', 'This note and its attachments will be permanently deleted.', 'Delete')) return;
  db.notes = db.notes.filter(x => x !== n); noteKeys.delete(n.id);
  ui.sel = null; scheduleSave(); renderAll();
}
async function emptyTrash() {
  if (!await yes('Empty the trash?', 'Every note in the trash will be permanently deleted.', 'Empty trash')) return;
  db.notes = db.notes.filter(n => !n.trashed);
  if (!cur()) ui.sel = null;
  scheduleSave(); renderAll();
}

/* ---------- Folders ---------- */
async function addFolder() {
  const r = await ask({ title: 'New folder', fields: [{ label: 'Folder name', type: 'text' }], ok: 'Create',
    action: ([v]) => { v = v.trim(); if (!v) throw new Error('Enter a name.'); return v.slice(0, 40); } });
  if (!r) return;
  db.folders.push({ id: uid(), name: r, color: '' });
  scheduleSave(); renderSide(); renderNote();
}
async function renameFolder(f) {
  const r = await ask({ title: 'Rename folder', fields: [{ label: 'Folder name', type: 'text', value: f.name }], ok: 'Rename',
    action: ([v]) => { v = v.trim(); if (!v) throw new Error('Enter a name.'); return v.slice(0, 40); } });
  if (!r) return;
  f.name = r; scheduleSave(); renderAll();
}
async function deleteFolder(f) {
  if (!await yes('Delete folder?', `The folder “${f.name}” will be removed. Its notes are kept and moved out of the folder.`, 'Delete folder')) return;
  db.notes.forEach(n => { if (n.folderId === f.id) n.folderId = null; });
  db.folders = db.folders.filter(x => x !== f);
  if (ui.view === 'f:' + f.id) ui.view = 'all';
  scheduleSave(); renderAll();
}

/* ---------- Locking, expiry, print ---------- */
async function lockNote(n) {
  if (n.locked) {                                                  // already protected: just close it
    await saveNow(); n.c = null; noteKeys.delete(n.id);
    renderAll(); return;
  }
  const r = await ask({
    title: 'Lock this note',
    text: 'Choose a PIN or password. The title, text, tags and attachments are encrypted with AES-256. If you forget it, the note cannot be recovered. A long password is much safer than a short PIN.',
    fields: [{ label: 'PIN or password' }, { label: 'Repeat it' }], ok: 'Lock note',
    action: async ([a, b]) => {
      if (a.length < 4) throw new Error('Use at least 4 characters.');
      if (a !== b) throw new Error('The two entries do not match.');
      const salt = rand(16);
      return { key: await derive(a, salt), salt: b64(salt) };
    }
  });
  if (!r) return;
  n.locked = true; noteKeys.set(n.id, r);
  await saveNow();
  n.c = null; noteKeys.delete(n.id);
  renderAll();
  toast('Note locked');
}
async function unlockNote(n, secret) {
  const key = await derive(secret, unb64(n.blob.s));
  n.c = await unseal(key, n.blob);                                 // throws if the secret is wrong
  noteKeys.set(n.id, { key, salt: n.blob.s });
}
async function doUnlock() {
  const n = cur(), pw = $('#unlockPw').value;
  if (!n || !pw) return;
  const b = $('#unlockBtn'); b.disabled = true;
  try { await unlockNote(n, pw); renderAll(); }
  catch { $('#unlockErr').textContent = 'Wrong PIN or password.'; }
  b.disabled = false;
}
async function removeLock(n) {
  if (!await yes('Remove the lock?', 'The note will be stored without its own PIN or password.', 'Remove lock')) return;
  n.locked = false; delete n.blob; noteKeys.delete(n.id);
  scheduleSave(); renderAll();
}
async function setExpiry(n) {
  const local = n.expiresAt ? new Date(n.expiresAt - new Date(n.expiresAt).getTimezoneOffset() * 6e4).toISOString().slice(0, 16) : '';
  const r = await ask({
    title: 'Set expiry', text: 'When this time passes, the note moves to the trash automatically.',
    fields: [{ label: 'Expiry date and time', type: 'datetime-local', value: local }], ok: 'Set expiry',
    extra: n.expiresAt ? { label: 'Clear expiry' } : null,
    action: ([v]) => {
      const t = new Date(v).getTime();
      if (!v || isNaN(t)) throw new Error('Pick a date and time.');
      if (t <= ts()) throw new Error('Choose a time in the future.');
      return t;
    }
  });
  if (r === null) return;
  n.expiresAt = typeof r === 'object' ? null : r;
  scheduleSave(); renderNote(); renderList();
}
function printNote(n) {
  const p = $('#printArea'), files = n.c.files;
  const tags = tagsOf(n).map(t => '#' + t).join(' ');
  p.replaceChildren(el('div', {},
    el('h1', {}, titleOf(n)),
    el('p', { class: 'pmeta' }, [tags, 'Edited ' + fmt(n.updated)].filter(Boolean).join(' · ')),
    el('div', { class: 'pbody' }, n.c.body),
    files.filter(f => f.type.startsWith('image/')).map(f => el('img', { src: f.data, alt: f.name })),
    files.length ? el('p', { class: 'pmeta' }, 'Attachments: ' + files.map(f => f.name).join(', ')) : null));
  const clear = () => { p.replaceChildren(); window.removeEventListener('afterprint', clear); };
  window.addEventListener('afterprint', clear);
  setTimeout(() => window.print(), 120);
}
function readFile(f) {
  return new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = () => rej(r.error); r.readAsDataURL(f); });
}

/* ---------- Vault (whole-app encryption) and backup ---------- */
function settings() {
  const d = $('#dlg'), f = $('#dlgForm');
  const item = (label, fn) => el('button', { type: 'button', class: 'wide', onclick: async () => { d.close(); await fn(); } }, label);
  f.onsubmit = e => { e.preventDefault(); d.close(); };
  d.oncancel = null;
  f.replaceChildren(el('div', {},
    el('h3', {}, 'Vault and backup'),
    el('p', { class: 'muted' }, vault
      ? 'Everything in this browser is encrypted with your vault passphrase.'
      : 'Right now your notes are stored as readable text in this browser. A vault passphrase encrypts everything, including titles, folders and attachments.'),
    vault ? [item('Change passphrase', setVault), item('Turn off vault encryption', removeVault)] : item('Set a vault passphrase', setVault),
    item('Export backup', exportBackup),
    item('Import backup…', () => $('#importFile').click()),
    el('div', { class: 'row end' }, el('button', { class: 'primary', type: 'submit' }, 'Done'))));
  d.showModal();
}
async function setVault() {
  const r = await ask({
    title: vault ? 'Change vault passphrase' : 'Set a vault passphrase',
    text: 'You will enter it each time you open the app. If you forget it, your notes cannot be recovered.',
    fields: [{ label: 'Passphrase (8 or more characters)' }, { label: 'Repeat passphrase' }], ok: 'Save',
    action: async ([a, b]) => {
      if (a.length < 8) throw new Error('Use at least 8 characters.');
      if (a !== b) throw new Error('The passphrases do not match.');
      const salt = rand(16);
      return { key: await derive(a, salt), salt: b64(salt) };
    }
  });
  if (!r) return;
  vault = r;
  toast((await saveNow()) ? 'Vault encryption is on.' : 'Could not save.');
}
async function removeVault() {
  if (!await yes('Turn off vault encryption?', 'Your notes will be stored without the vault passphrase. Locked notes keep their own PIN or password.', 'Turn off')) return;
  vault = null;
  toast((await saveNow()) ? 'Vault encryption is off.' : 'Could not save.');
}
async function exportBackup() {
  await saveNow();
  saveBlob(new Blob([localStorage.getItem(KEY) || '{}'], { type: 'application/json' }),
    `localeasynotepad-backup-${new Date().toISOString().slice(0, 10)}.json`);
}
async function importBackup(file) {
  try {
    const txt = await file.text(), d = JSON.parse(txt);
    if (!d || d.v !== 1 || !(d.enc || Array.isArray(d.notes))) throw 0;
    if (!await yes('Replace all notes?', 'Importing replaces every note in this browser with the backup. Export first if you want to keep the current notes.', 'Import')) return;
    frozen = true;
    localStorage.setItem(KEY, txt);
    location.reload();
  } catch { toast('That file is not a valid backup.'); }
}

/* ---------- Theme ---------- */
function applyTheme(t) {
  if (t) { document.documentElement.dataset.theme = t; try { localStorage.setItem(THEME_KEY, t); } catch {} }
  const dark = document.documentElement.dataset.theme === 'dark' ||
    (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: dark)').matches);
  const b = $('#themeBtn');
  b.replaceChildren(ico(dark ? 'sun' : 'moon'));
  b.dataset.dark = dark ? '1' : '';
}

/* ---------- Expiry and trash clean-up ---------- */
function sweep() {
  const t = ts(); let changed = false;
  for (const n of db.notes) if (!n.trashed && n.expiresAt && n.expiresAt <= t) { n.trashed = true; n.trashedAt = t; changed = true; }
  const before = db.notes.length;
  db.notes = db.notes.filter(n => !(n.trashed && t - (n.trashedAt || t) > TRASH_DAYS * 864e5));
  if (db.notes.length !== before) changed = true;
  if (changed) { scheduleSave(); if (!cur()) ui.sel = null; renderAll(); }
}

/* ---------- Startup ---------- */
function normalize(data) {
  db.folders = (data.folders || []).map(f => ({ id: f.id, name: String(f.name || 'Folder'), color: COLORS.includes(f.color) ? f.color : '' }));
  db.notes = (data.notes || []).map(n => {
    n.color = COLORS.includes(n.color) ? n.color : '';
    n.pinned = !!n.pinned; n.trashed = !!n.trashed; n.expiresAt = n.expiresAt || null;
    n.created = n.created || ts(); n.updated = n.updated || n.created;
    if (n.folderId && !db.folders.some(f => f.id === n.folderId)) n.folderId = null;
    n.c = n.locked ? null : { title: '', body: '', tags: [], files: [], ...n.c };
    return n;
  });
}
async function load() {
  const raw = localStorage.getItem(KEY);
  if (!raw) return { notes: [], folders: [] };
  let d;
  try { d = JSON.parse(raw); } catch { localStorage.setItem(KEY + '.corrupt', raw); toast('Stored data was unreadable. A copy was kept.'); return { notes: [], folders: [] }; }
  if (!d.enc) return d;
  for (;;) {
    const r = await ask({
      title: 'Unlock your notes', text: 'Enter your vault passphrase to open LocalEasyNotepad.',
      fields: [{ label: 'Vault passphrase' }], ok: 'Unlock', cancel: false, extra: { label: 'Erase everything…' },
      action: async ([p]) => {
        try { const key = await derive(p, unb64(d.s)); const out = await unseal(key, d); vault = { key, salt: d.s }; return out; }
        catch { throw new Error('Wrong passphrase.'); }
      }
    });
    if (r && r.extra) {
      if (await yes('Erase everything?', 'This permanently deletes all notes stored in this browser. It cannot be undone.', 'Erase all')) {
        localStorage.removeItem(KEY); return { notes: [], folders: [] };
      }
      continue;
    }
    return r;
  }
}

function wire() {
  document.querySelectorAll('[data-ico]').forEach(b => b.prepend(ico(b.dataset.ico)));

  $('#newBtn').onclick = $('#newBtn2').onclick = $('#newBtn3').onclick = newNote;
  $('#addFolder').onclick = addFolder;
  $('#emptyTrash').onclick = emptyTrash;
  $('#themeBtn').onclick = () => applyTheme($('#themeBtn').dataset.dark ? 'light' : 'dark');
  $('#vaultBtn').onclick = settings;
  $('#menuBtn').onclick = () => $('#app').classList.add('menu');
  $('#scrim').onclick = () => $('#app').classList.remove('menu');
  $('#backBtn').onclick = () => $('#app').classList.remove('editing');
  $('#search').oninput = e => { ui.q = e.target.value; renderList(); };
  $('#importFile').onchange = e => { const f = e.target.files[0]; e.target.value = ''; if (f) importBackup(f); };

  // Toolbar
  $('#pinBtn').onclick = () => { const n = cur(); n.pinned = !n.pinned; scheduleSave(); renderNote(); renderList(); renderSide(); };
  $('#folderSel').onchange = e => { const n = cur(); n.folderId = e.target.value || null; scheduleSave(); renderSide(); renderList(); };
  $('#expBtn').onclick = () => setExpiry(cur());
  $('#lockBtn').onclick = () => lockNote(cur());
  $('#unlockRemoveBtn').onclick = () => removeLock(cur());
  $('#dupBtn').onclick = () => duplicateNote(cur());
  $('#printBtn').onclick = () => printNote(cur());
  $('#attachBtn').onclick = () => $('#fileIn').click();
  $('#trashBtn').onclick = () => trashNote(cur());
  $('#restoreBtn').onclick = () => restoreNote(cur(), false);
  $('#purgeBtn').onclick = () => purgeNote(cur());
  $('#unlockBtn').onclick = doUnlock;
  $('#unlockPw').onkeydown = e => { if (e.key === 'Enter') doUnlock(); };

  // Editing with autosave
  $('#title').oninput = e => { const n = cur(); if (!n || !n.c) return; n.c.title = e.target.value; touch(n); renderMeta(n); refresh(); };
  $('#body').oninput = e => { const n = cur(); if (!n || !n.c) return; n.c.body = e.target.value; touch(n); renderMeta(n); renderTags(n); refresh(); };
  $('#tagIn').onkeydown = e => {
    const n = cur(), input = e.target;
    if (['Enter', ',', ' '].includes(e.key) && input.value.trim()) { e.preventDefault(); addTag(n, input.value); input.value = ''; }
    else if (e.key === 'Backspace' && !input.value && n.c.tags.length) { n.c.tags.pop(); touch(n); renderTags(n); refresh(); }
  };
  $('#tagIn').onblur = e => { const n = cur(); if (n && n.c && e.target.value.trim()) { addTag(n, e.target.value); e.target.value = ''; } };

  // Attachments
  $('#fileIn').onchange = async e => {
    const n = cur(), files = [...e.target.files]; e.target.value = '';
    if (!n || !n.c) return;
    for (const f of files) {
      if (f.size > MAX_FILE) { toast(`“${f.name}” is larger than ${fmtSize(MAX_FILE)}.`); continue; }
      const att = { id: uid(), name: f.name, type: f.type || 'application/octet-stream', size: f.size, data: await readFile(f) };
      n.c.files.push(att); touch(n);
      if (!(await saveNow())) { n.c.files.pop(); scheduleSave(); }
    }
    if (cur() === n) { renderFiles(n); renderList(); }
  };

  // Keyboard shortcuts: Alt+N new note, Ctrl/Cmd+S save now
  document.addEventListener('keydown', e => {
    if (e.altKey && e.code === 'KeyN') { e.preventDefault(); newNote(); }
    else if ((e.ctrlKey || e.metaKey) && e.code === 'KeyS') { e.preventDefault(); saveNow().then(() => toast('Saved')); }
  });
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden' && dirty) saveNow(); });
  window.addEventListener('pagehide', () => { if (dirty) saveNow(); });
  window.addEventListener('beforeunload', e => { if (dirty && !frozen) { e.preventDefault(); e.returnValue = ''; } });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => applyTheme());
}

async function init() {
  wire();
  applyTheme();
  if (!window.crypto || !crypto.subtle) {
    document.body.textContent = 'This browser does not support the Web Crypto API (it needs https, localhost or a local file).';
    return;
  }
  normalize(await load());
  renderAll(); meter();
  sweep(); setInterval(sweep, 30000);
  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('sw.js').catch(() => {});
}
init().catch(e => { document.body.textContent = 'Startup error: ' + e.message; });
})();
