import { invoke } from "@tauri-apps/api/tauri";
import { open, save } from "@tauri-apps/api/dialog";

const operationEl = document.querySelector("#operation");
const modeEl = document.querySelector("#mode");
const inputPathEl = document.querySelector("#inputPath");
const outputPathEl = document.querySelector("#outputPath");
const passwordEl = document.querySelector("#password");
const keyPathEl = document.querySelector("#keyPath");
const keyWrapEl = document.querySelector("#keyWrap");
const outputWrapEl = document.querySelector("#outputWrap");
const statusEl = document.querySelector("#status");

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? "#ff9ea8" : "#d9f4ff";
}

function syncUiState() {
  const operation = operationEl.value;
  const mode = modeEl.value;
  const isVerify = operation === "verify";
  const isKyber = mode === "kyber" && !isVerify;

  outputWrapEl.classList.toggle("hidden", isVerify);
  keyWrapEl.classList.toggle("hidden", !isKyber);
}

async function pickOpenPath(targetEl) {
  const selected = await open({ multiple: false });
  if (typeof selected === "string") {
    targetEl.value = selected;
  }
}

async function pickSavePath(targetEl) {
  const selected = await save({});
  if (typeof selected === "string") {
    targetEl.value = selected;
  }
}

async function runAction() {
  try {
    const operation = operationEl.value;
    const mode = modeEl.value;
    const inputPath = inputPathEl.value.trim();
    const outputPath = outputPathEl.value.trim();
    const password = passwordEl.value;
    const keyPath = keyPathEl.value.trim() || null;

    if (!inputPath) {
      setStatus("Input dosyasi zorunlu.", true);
      return;
    }

    if (operation === "verify") {
      const result = await invoke("verify_file", { inputPath });
      setStatus(result);
      return;
    }

    if (!outputPath) {
      setStatus("Output dosyasi zorunlu.", true);
      return;
    }

    if (!password) {
      setStatus("Parola zorunlu.", true);
      return;
    }

    setStatus("Calisiyor...");

    if (operation === "encrypt") {
      const result = await invoke("encrypt_file", {
        inputPath,
        outputPath,
        password,
        mode,
        keyPath,
      });
      setStatus(result);
      passwordEl.value = "";
      return;
    }

    if (operation === "decrypt") {
      const result = await invoke("decrypt_file", {
        inputPath,
        outputPath,
        password,
        mode,
        keyPath,
      });
      setStatus(result);
      passwordEl.value = "";
      return;
    }
  } catch (error) {
    setStatus(String(error), true);
  }
}

async function validatePassword() {
  try {
    const password = passwordEl.value;
    if (!password) {
      setStatus("Parola girin.", true);
      return;
    }
    const result = await invoke("validate_password_cmd", { password });
    setStatus(result);
  } catch (error) {
    setStatus(String(error), true);
  }
}

document.querySelector("#pickInput").addEventListener("click", () => pickOpenPath(inputPathEl));
document.querySelector("#pickOutput").addEventListener("click", () => pickSavePath(outputPathEl));
document.querySelector("#pickKey").addEventListener("click", () => pickSavePath(keyPathEl));
document.querySelector("#runAction").addEventListener("click", runAction);
document.querySelector("#validatePassword").addEventListener("click", validatePassword);
operationEl.addEventListener("change", syncUiState);
modeEl.addEventListener("change", syncUiState);

syncUiState();
