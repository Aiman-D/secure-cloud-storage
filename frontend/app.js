// Secure Cloud Storage - browser app.
// Talks to Cognito (sign-in), our API Gateway (file operations) and S3 (via short-lived links).
// All user-supplied text is inserted with textContent, never innerHTML, to prevent XSS.
(() => {
  "use strict";

  const CFG = window.APP_CONFIG || {};
  const TOKEN_KEY = "scs.idToken";
  const STATUS_REFRESH_MS = 10000;
  const $ = (id) => document.getElementById(id);

  let idToken = null;
  let statusTimer = null;
  let seenFixTimes = new Set();
  let firstStatusLoad = true;

  // ------------------------------------------------------------------ helpers
  const store = {
    get() { try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; } },
    set(v) { try { sessionStorage.setItem(TOKEN_KEY, v); } catch { /* private mode */ } },
    clear() { try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ } },
  };

  function el(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    for (const child of [].concat(children)) if (child) node.append(child);
    return node;
  }

  function decodeJwt(token) {
    try {
      let part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      while (part.length % 4) part += "=";
      return JSON.parse(atob(part));
    } catch {
      return null;
    }
  }

  function tokenValid(token) {
    const claims = token && decodeJwt(token);
    return !!claims && claims.exp * 1000 > Date.now() + 30000;
  }

  function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB"];
    let value = bytes / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
    return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
  }

  function formatDate(iso) {
    return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function timeAgo(iso) {
    const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
    return formatDate(iso);
  }

  let toastTimer;
  function toast(message, isError = false) {
    const box = $("toast");
    box.textContent = message;
    box.classList.toggle("error", isError);
    box.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => box.classList.remove("show"), 3500);
  }

  // ------------------------------------------------------------------ auth (Cognito)
  async function signIn(username, password) {
    const res = await fetch(`https://cognito-idp.${CFG.region}.amazonaws.com/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
      },
      body: JSON.stringify({
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: CFG.userPoolClientId,
        AuthParameters: { USERNAME: username, PASSWORD: password },
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const type = String(data.__type || "");
      if (type.includes("NotAuthorized") || type.includes("UserNotFound")) throw new Error("Wrong username or password.");
      if (type.includes("TooManyRequests") || type.includes("LimitExceeded")) throw new Error("Too many attempts. Wait a minute and try again.");
      throw new Error(data.message || "Sign-in failed.");
    }
    if (data.ChallengeName) throw new Error("This account needs a password reset by the administrator.");
    return data.AuthenticationResult.IdToken;
  }

  function signOut(message) {
    idToken = null;
    store.clear();
    clearInterval(statusTimer);
    $("app-view").hidden = true;
    $("user-area").hidden = true;
    $("login-view").hidden = false;
    $("password").value = "";
    $("login-error").textContent = message || "";
  }

  // ------------------------------------------------------------------ API
  async function api(path, options = {}) {
    if (!tokenValid(idToken)) {
      signOut("Your session expired. Please sign in again.");
      throw new Error("Session expired");
    }
    const res = await fetch(CFG.apiUrl + path, {
      ...options,
      headers: { Authorization: idToken, "Content-Type": "application/json", ...(options.headers || {}) },
    });
    if (res.status === 401) {
      signOut("Your session expired. Please sign in again.");
      throw new Error("Session expired");
    }
    if (res.status === 429) throw new Error("Too many requests (rate limit). Slow down a little.");
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  // ------------------------------------------------------------------ files
  async function loadFiles() {
    try {
      const { files } = await api("/files");
      renderFiles(files);
    } catch (err) {
      if (err.message !== "Session expired") toast(err.message, true);
    }
  }

  function renderFiles(files) {
    const body = $("files-body");
    body.replaceChildren();
    $("files-empty").hidden = files.length > 0;
    for (const file of files) {
      const download = el("button", { class: "btn btn-ghost", type: "button", text: "Download", onclick: () => downloadFile(file.name) });
      const remove = el("button", { class: "btn btn-ghost", type: "button", text: "Delete" });
      remove.addEventListener("click", () => armDelete(remove, file.name));
      body.append(el("tr", {}, [
        el("td", { class: "name", title: file.name, text: file.name }),
        el("td", { class: "num", text: formatSize(file.size) }),
        el("td", { text: formatDate(file.lastModified) }),
        el("td", { class: "actions" }, [download, remove]),
      ]));
    }
  }

  async function downloadFile(name) {
    try {
      const { url } = await api(`/download-url?name=${encodeURIComponent(name)}`);
      window.location.assign(url);
      toast(`Downloading ${name} (link expires in 5 minutes)`);
    } catch (err) {
      if (err.message !== "Session expired") toast(err.message, true);
    }
  }

  // Two-click delete instead of a browser confirm() dialog
  function armDelete(button, name) {
    if (button.dataset.armed === "1") {
      button.disabled = true;
      api(`/files?name=${encodeURIComponent(name)}`, { method: "DELETE" })
        .then(() => { toast(`Deleted ${name}`); loadFiles(); })
        .catch((err) => { if (err.message !== "Session expired") toast(err.message, true); button.disabled = false; });
      return;
    }
    button.dataset.armed = "1";
    button.textContent = "Confirm";
    button.classList.add("btn-danger-armed");
    setTimeout(() => {
      button.dataset.armed = "";
      button.textContent = "Delete";
      button.classList.remove("btn-danger-armed");
    }, 3000);
  }

  // ------------------------------------------------------------------ uploads
  const maxBytes = () => (CFG.maxUploadMb || 10) * 1024 * 1024;

  function uploadFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    Promise.all(files.map(uploadOne)).then(loadFiles);
  }

  async function uploadOne(file) {
    const state = el("span", { class: "state muted", text: "Preparing…" });
    const fill = el("span");
    const row = el("li", {}, [
      el("div", { class: "upload-row" }, [el("span", { class: "name", text: file.name }), state]),
      el("div", { class: "bar" }, [fill]),
    ]);
    $("uploads").prepend(row);

    const fail = (message) => {
      row.classList.add("failed");
      state.textContent = message;
    };

    if (file.size === 0) return fail("Empty file");
    if (file.size > maxBytes()) return fail(`Over ${CFG.maxUploadMb || 10} MB limit`);

    try {
      const form = await api("/upload-url", {
        method: "POST",
        body: JSON.stringify({ name: file.name, size: file.size, type: file.type || "application/octet-stream" }),
      });
      state.textContent = "Uploading…";
      await postToS3(form, file, (pct) => { fill.style.width = `${pct}%`; });
      fill.style.width = "100%";
      row.classList.add("done");
      state.textContent = "Encrypted & stored";
      setTimeout(() => row.remove(), 6000);
    } catch (err) {
      fail(err.message === "Session expired" ? "Session expired" : err.message || "Upload failed");
    }
  }

  // Upload straight to S3 using the presigned POST form. S3 itself enforces the size limit.
  function postToS3(form, file, onProgress) {
    return new Promise((resolve, reject) => {
      const data = new FormData();
      for (const [key, value] of Object.entries(form.fields)) data.append(key, value);
      data.append("file", file);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", form.url);
      xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
      });
      xhr.addEventListener("load", () => (xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error(`S3 rejected the upload (${xhr.status})`))));
      xhr.addEventListener("error", () => reject(new Error("Network error during upload")));
      xhr.send(data);
    });
  }

  function setupDropzone() {
    const zone = $("dropzone");
    const input = $("file-input");
    input.addEventListener("change", () => { uploadFiles(input.files); input.value = ""; });
    ["dragenter", "dragover"].forEach((type) => zone.addEventListener(type, (e) => {
      e.preventDefault();
      zone.classList.add("dragging");
    }));
    ["dragleave", "drop"].forEach((type) => zone.addEventListener(type, (e) => {
      e.preventDefault();
      zone.classList.remove("dragging");
    }));
    zone.addEventListener("drop", (e) => uploadFiles(e.dataTransfer.files));
  }

  // ------------------------------------------------------------------ security status
  async function loadStatus() {
    try {
      const data = await api("/status");
      renderStatus(data);
    } catch (err) {
      if (err.message !== "Session expired") $("checked-at").textContent = `Status unavailable: ${err.message}`;
    }
  }

  function renderStatus(data) {
    const allOk = data.checks.every((c) => c.ok);
    const overall = $("overall");
    overall.textContent = allOk ? "Protected" : "At risk";
    overall.className = `pill ${allOk ? "ok" : "bad"}`;

    $("checks").replaceChildren(...data.checks.map((check) => el("li", { class: check.ok ? "ok" : "bad" }, [
      el("span", { class: "icon", "aria-hidden": "true", text: check.ok ? "✓" : "!" }),
      el("span", { class: "label", text: check.label }),
      el("span", { class: "detail", text: check.detail }),
    ])));

    const fixes = data.recentFixes || [];
    const list = $("fixes");
    if (!fixes.length) {
      list.replaceChildren(el("li", { class: "muted", text: "None yet. Try turning off Block Public Access on the bucket." }));
    } else {
      list.replaceChildren(...fixes.map((fix) => {
        const fresh = !firstStatusLoad && !seenFixTimes.has(fix.time);
        return el("li", { class: fresh ? "fresh" : "" }, [
          el("div", {}, [el("span", { class: "when", text: timeAgo(fix.time) }), document.createTextNode(` re-locked ${fix.bucket}`)]),
          el("div", { class: "who", text: `changed by ${fix.actor}` }),
        ]);
      }));
      const newest = fixes.find((fix) => !seenFixTimes.has(fix.time));
      if (newest && !firstStatusLoad) toast(`Auto-fix: public access was re-blocked on ${newest.bucket}`);
      fixes.forEach((fix) => seenFixTimes.add(fix.time));
    }
    firstStatusLoad = false;
    $("checked-at").textContent = `Live check every ${STATUS_REFRESH_MS / 1000}s · last ${new Date(data.checkedAt).toLocaleTimeString()}`;
  }

  // ------------------------------------------------------------------ app start
  function showApp() {
    const claims = decodeJwt(idToken) || {};
    $("user-name").textContent = claims["cognito:username"] || "";
    $("login-view").hidden = true;
    $("app-view").hidden = false;
    $("user-area").hidden = false;
    $("login-error").textContent = "";
    firstStatusLoad = true;
    seenFixTimes = new Set();
    loadFiles();
    loadStatus();
    clearInterval(statusTimer);
    statusTimer = setInterval(loadStatus, STATUS_REFRESH_MS);
  }

  function init() {
    $("services").replaceChildren(...(CFG.services || []).map((name) => el("li", { text: name })));
    $("upload-limit").textContent = `Max ${CFG.maxUploadMb || 10} MB per file`;

    if (!CFG.apiUrl || !CFG.userPoolClientId) {
      $("login-error").textContent = "Website configuration missing (config.js). Re-run terraform apply.";
      $("login-btn").disabled = true;
      return;
    }

    $("login-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const username = $("username").value.trim();
      const password = $("password").value;
      if (!username || !password) {
        $("login-error").textContent = "Enter your username and password.";
        return;
      }
      const button = $("login-btn");
      button.disabled = true;
      button.textContent = "Signing in…";
      $("login-error").textContent = "";
      try {
        idToken = await signIn(username, password);
        store.set(idToken);
        showApp();
      } catch (err) {
        $("login-error").textContent = err.message;
      } finally {
        button.disabled = false;
        button.textContent = "Sign in";
      }
    });

    $("logout-btn").addEventListener("click", () => signOut());
    $("refresh-files").addEventListener("click", loadFiles);
    setupDropzone();

    const saved = store.get();
    if (tokenValid(saved)) {
      idToken = saved;
      showApp();
    }
  }

  init();
})();
