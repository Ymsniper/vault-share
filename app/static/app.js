// Small additions to the pages. Every page still works without them.
// Served from this site, so the Content-Security-Policy lets it run.

const EYE =
  '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" ' +
  'stroke-width="1.5" aria-hidden="true"><path d="M1 8s2.5-5 7-5 7 5 7 5-2.5 5-7 5-7-5-7-5z"/>' +
  '<circle cx="8" cy="8" r="2.2"/></svg>';
const EYE_SLASH = EYE.replace("</svg>", '<path d="M2 2l12 12"/></svg>');

// An eye button that shows or hides what was typed. A field marked "masked"
// is a text field hidden with CSS (so password managers leave it alone):
// for it the button toggles the class instead of the type.
function addRevealButton(input) {
  const group = document.createElement("div");
  group.className = "input-group";
  input.replaceWith(group);
  group.append(input);

  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn-outline-secondary";
  group.append(button);

  const masked = input.classList.contains("masked");
  const isHidden = () => (masked ? input.classList.contains("masked") : input.type === "password");
  const render = () => {
    button.innerHTML = isHidden() ? EYE : EYE_SLASH;
    button.setAttribute("aria-label", isHidden() ? "Show what I typed" : "Hide what I typed");
  };
  button.addEventListener("click", () => {
    if (masked) {
      input.classList.toggle("masked");
    } else {
      input.type = input.type === "password" ? "text" : "password";
    }
    render();
    input.focus();
  });
  render();
}

// A button that clears the chosen file, shown only once a file is chosen.
function addRemoveFileButton(input) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn-outline-secondary btn-sm mt-2";
  button.textContent = "Remove file";
  input.after(button);

  const render = () => {
    button.hidden = input.files.length === 0;
  };
  button.addEventListener("click", () => {
    input.value = "";
    render();
  });
  input.addEventListener("change", render);
  render();
}

// A Copy button after a new invite code and after the two-factor key. Where
// the page has no clipboard access (plain HTTP), the text is selected
// instead, ready for Ctrl+C.
function addCopyButton(el) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn-outline-secondary btn-sm vs-copy";
  button.setAttribute("aria-live", "polite");
  button.textContent = "Copy";
  el.after(button);

  let timer;
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(el.textContent.trim());
      button.textContent = "Copied";
    } catch {
      getSelection().selectAllChildren(el);
      button.textContent = "Selected";
    }
    clearTimeout(timer);
    timer = setTimeout(() => (button.textContent = "Copy"), 1600);
  });
}

// The upload page's drop area lights up while a file is dragged over it.
function addDropHighlight(input) {
  const on = () => input.classList.add("is-dragover");
  const off = () => input.classList.remove("is-dragover");
  input.addEventListener("dragenter", on);
  input.addEventListener("dragover", on);
  input.addEventListener("dragleave", off);
  input.addEventListener("drop", off);
}

// ASCII art "decrypts": characters taken from the art itself flicker in
// place and settle from left to right. The text keeps its length, so
// nothing on the page moves.
function decrypt(pre) {
  const text = pre.textContent;
  const pool = [...new Set(text.replace(/\s/g, ""))];
  if (pool.length < 2) {
    return;
  }
  const cells = [...text];
  const cols = Math.max(...text.split("\n").map((line) => line.length));
  const settle = [];
  let col = 0;
  for (const c of cells) {
    settle.push(c.trim() ? (col / cols) * 0.7 + Math.random() * 0.3 : 0);
    col = c === "\n" ? 0 : col + 1;
  }
  const noise = (t) =>
    cells.map((c, i) => (t >= settle[i] ? c : pool[(Math.random() * pool.length) | 0])).join("");

  const duration = 750;
  let start;
  let last = 0;
  let finished = false;
  const finish = () => {
    finished = true;
    pre.textContent = text;
  };
  // the art never stays scrambled, even where animation frames stop
  setTimeout(finish, duration + 400);
  pre.textContent = noise(0);
  const frame = (now) => {
    if (finished) {
      return;
    }
    start ??= now;
    const t = (now - start) / duration;
    if (t >= 1) {
      finish();
      return;
    }
    // new noise about 20 times a second: calmer than every frame
    if (now - last >= 50) {
      last = now;
      pre.textContent = noise(t);
    }
    requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

// the header's wordmark decrypts on the first page of a browser session only
function firstPageOfSession() {
  try {
    if (sessionStorage.getItem("vs-decrypted")) {
      return false;
    }
    sessionStorage.setItem("vs-decrypted", "1");
    return true;
  } catch {
    return false;
  }
}

for (const input of document.querySelectorAll('input[type="password"], input.masked')) {
  addRevealButton(input);
}
for (const input of document.querySelectorAll('input[type="file"]')) {
  addRemoveFileButton(input);
}
for (const input of document.querySelectorAll("input.vs-drop")) {
  addDropHighlight(input);
}
for (const el of document.querySelectorAll(".vs-invite-code")) {
  addCopyButton(el);
}
for (const el of document.querySelectorAll("code")) {
  if (/^[A-Z2-7]{32}$/.test(el.textContent)) {
    addCopyButton(el);
  }
}

// While the next page loads, a line grows under the menu (vault.css). A
// download stays on this page, so its form and link are marked
// data-download and left out.
const loading = () => document.documentElement.classList.add("vs-loading");

document.addEventListener("submit", (e) => {
  if (!e.defaultPrevented && !e.target.hasAttribute("data-download")) {
    loading();
  }
});

document.addEventListener("click", (e) => {
  const a = e.target.closest("a[href]");
  if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
    return;
  }
  if (a.target || a.hasAttribute("download") || a.hasAttribute("data-download")) {
    return;
  }
  const url = new URL(a.href, location.href);
  const samePage = url.pathname === location.pathname && url.search === location.search;
  if (url.origin === location.origin && !(samePage && url.hash)) {
    loading();
  }
});

// a page shown again by Back starts without the line
addEventListener("pageshow", (e) => {
  if (e.persisted) {
    document.documentElement.classList.remove("vs-loading");
  }
});

// only for someone looking: not with reduced motion, not in a hidden tab
if (!matchMedia("(prefers-reduced-motion: reduce)").matches && document.visibilityState === "visible") {
  const shown = [...document.querySelectorAll(".vs-banner .vs-ascii")].filter(
    (pre) => pre.getClientRects().length > 0,
  );
  if (shown.length && firstPageOfSession()) {
    shown.forEach(decrypt);
  }
  document.querySelectorAll(".vs-error-art").forEach(decrypt);
}
