"use strict";

// All user-controlled text is inserted with textContent, never innerHTML.

const form = document.getElementById("check");
const textarea = document.getElementById("text");
const submit = document.getElementById("submit");
const result = document.getElementById("result");
const template = document.getElementById("link-template");

const BADGES = {
  official: { label: "Official domain", cls: "is-official" },
  impersonation_signals: { label: "Impersonation signals", cls: "is-danger" },
  not_recognised: { label: "Not recognised", cls: "is-unknown" },
  cannot_check: { label: "Cannot check", cls: "is-muted" },
};

const SIGNAL_TITLES = {
  userinfo_trick: "Hidden real address",
  deceptive_suffix: "Official name in the wrong place",
  namespace_lookalike: "Fake namespace",
  brand_token: "Uses an official name",
  lookalike_label: "Lookalike spelling",
  mixed_script: "Mixed alphabets",
  claim_mismatch: "Message and link disagree",
  lure_words: "Phishing-style words",
  raw_ip: "Bare IP address",
};

const ADVICE = {
  impersonation_signals: [
    "Do not open the link or enter any details.",
    "Reach your bank or the department through its official app or by typing its address yourself.",
    "Report the message on Sanchar Saathi (Chakshu). If you have lost money, call 1930 now.",
  ],
  cannot_check: [
    "Do not open shortened links from unexpected messages.",
    "Go to the organisation's official site or app yourself.",
  ],
  not_recognised: [
    "Not recognised is not the same as safe. Do not enter bank details, OTPs or PINs on this site.",
    "If the message claims to be from a bank or government office, reach them through their official app instead.",
  ],
  official: [
    "The address belongs to the organisation shown. Still, no bank or department asks for your OTP, PIN or password.",
  ],
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setBusy(busy) {
  result.setAttribute("aria-busy", String(busy));
  submit.disabled = busy;
  submit.textContent = busy ? "Checking…" : "Check";
}

function renderMessage(cls, title, body) {
  result.replaceChildren();
  const box = el("div", `card notice ${cls}`);
  box.append(el("p", "notice-title", title));
  if (body) box.append(el("p", "hint", body));
  result.append(box);
}

function renderLink(link) {
  const node = template.content.firstElementChild.cloneNode(true);
  const badge = BADGES[link.verdict] || BADGES.not_recognised;
  node.classList.add(badge.cls);
  node.querySelector(".badge").textContent = badge.label;
  node.querySelector(".link-headline").textContent = link.headline;

  const host = link.host || "";
  const owner = link.registrable || host;
  const ownerAt = owner ? host.lastIndexOf(owner) : -1;
  node.querySelector(".host-sub").textContent = ownerAt > 0 ? host.slice(0, ownerAt) : "";
  node.querySelector(".host-owner").textContent = ownerAt >= 0 ? host.slice(ownerAt) : host;
  node.querySelector(".owner-note").textContent = link.registrable
    ? `The part in bold, ${link.registrable}, is who actually owns this address.`
    : "";

  const signals = node.querySelector(".signals");
  for (const signal of link.signals) {
    const item = el("li", `signal signal-${signal.id}`);
    item.append(el("strong", null, SIGNAL_TITLES[signal.id] || signal.id), el("span", null, signal.message));
    signals.append(item);
  }
  if (!signals.children.length) signals.remove();

  const notes = node.querySelector(".notes");
  for (const note of link.notes) notes.append(el("li", null, note));
  if (!notes.children.length) notes.remove();
  return node;
}

function renderResult(data) {
  result.replaceChildren();
  if (!data.links.length) {
    renderMessage("is-muted", "No link found.", "Paste a full address (for example https://…) or the whole message.");
    return;
  }
  const badge = BADGES[data.verdict] || BADGES.not_recognised;
  const summary = el("div", `card summary ${badge.cls}`);
  summary.append(el("p", "summary-label", badge.label), el("h2", "summary-headline", data.headline));
  if (data.claims.length) {
    summary.append(el("p", "hint", `The message mentions: ${data.claims.join(", ")}.`));
  }
  const advice = ADVICE[data.verdict] || [];
  if (advice.length) {
    const list = el("ul", "advice");
    for (const line of advice) list.append(el("li", null, line));
    summary.append(list);
  }
  result.append(summary);
  for (const link of data.links) {
    const card = renderLink(link);
    // With one link the summary already carries the verdict; the card keeps only the evidence.
    if (data.links.length === 1) card.classList.add("single");
    result.append(card);
  }
  summary.setAttribute("tabindex", "-1");
  summary.focus({ preventScroll: false });
}

async function check(text) {
  setBusy(true);
  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (response.status === 422) {
      const body = await response.json().catch(() => ({}));
      const detail = typeof body.detail === "string" ? body.detail : "The text could not be read.";
      renderMessage("is-muted", "Could not check that.", detail);
      return;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderResult(await response.json());
  } catch (error) {
    renderMessage("is-muted", "The check could not be completed.", "Please try again in a moment.");
  } finally {
    setBusy(false);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = textarea.value.trim();
  if (!text) {
    renderMessage("is-muted", "Paste a link or a message first.");
    textarea.focus();
    return;
  }
  check(text);
});

for (const chip of document.querySelectorAll("[data-sample]")) {
  chip.addEventListener("click", () => {
    textarea.value = chip.dataset.sample;
    check(textarea.value);
  });
}

fetch("/api/health")
  .then((r) => (r.ok ? r.json() : null))
  .then((data) => {
    if (data) document.getElementById("registry-version").textContent = data.registry_version;
  })
  .catch(() => {});
