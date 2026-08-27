"use strict";

const inputEl = document.getElementById("input");
const decodeBtn = document.getElementById("decodeBtn");
const clearBtn = document.getElementById("clearBtn");
const statusEl = document.getElementById("status");
const errorEl = document.getElementById("error");
const outputEl = document.getElementById("output");

let pyRun = null;

function showError(message) {
  errorEl.textContent = message;
  errorEl.hidden = false;
}

function clearError() {
  errorEl.hidden = true;
  errorEl.textContent = "";
}

function renderResult(result) {
  outputEl.innerHTML = "";

  if (!result.ok) {
    showError(result.error || "Unknown error.");
    return;
  }
  clearError();

  result.messages.forEach((text, i) => {
    const block = document.createElement("div");
    block.className = "message";

    const heading = document.createElement("h2");
    heading.textContent = `Message ${i + 1}`;
    block.appendChild(heading);

    const pre = document.createElement("pre");
    pre.textContent = text;
    block.appendChild(pre);

    outputEl.appendChild(block);
  });

  if (result.error) {
    const warn = document.createElement("div");
    warn.className = "warning";
    warn.textContent = `${result.error}. ${result.leftover_bytes} byte(s) left undecoded.`;
    outputEl.appendChild(warn);
  }

  const summary = document.createElement("p");
  summary.className = "summary";
  summary.textContent = `Decoded ${result.count} message(s), ${result.leftover_bytes} byte(s) left over (${result.byte_count} byte(s) total input).`;
  outputEl.appendChild(summary);
}

function handleClearClick() {
  inputEl.value = "";
  outputEl.innerHTML = "";
  clearError();
  inputEl.focus();
}

async function handleDecodeClick() {
  const text = inputEl.value;
  if (!text.trim()) {
    outputEl.innerHTML = "";
    showError("Paste a hex dump first.");
    return;
  }

  try {
    const json = pyRun(text);
    const result = JSON.parse(json);
    renderResult(result);
  } catch (exc) {
    outputEl.innerHTML = "";
    showError(`Unexpected error while decoding: ${exc}`);
  }
}

async function bootstrap() {
  try {
    statusEl.textContent = "Loading Python runtime…";
    const pyodide = await loadPyodide();

    statusEl.textContent = "Loading micropip…";
    await pyodide.loadPackage("micropip");
    const micropip = pyodide.pyimport("micropip");

    statusEl.textContent = "Installing pyasn1_ldap from PyPI…";
    await micropip.install("pyasn1_ldap");

    statusEl.textContent = "Loading application code…";
    const src = await (await fetch("./app.py")).text();
    pyodide.runPython(src);
    pyRun = pyodide.globals.get("run");

    statusEl.textContent = "Ready.";
    decodeBtn.disabled = false;
  } catch (exc) {
    statusEl.textContent =
      `Failed to load: ${exc}. Check network access to pypi.org / files.pythonhosted.org.`;
  }
}

decodeBtn.addEventListener("click", handleDecodeClick);
clearBtn.addEventListener("click", handleClearClick);
bootstrap();
