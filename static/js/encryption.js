// static/js/encryption.js

// ======= Helpers for base64 / buffers =======

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ======= Fallback toast/loading for pages that don't define them =======

if (typeof showToast !== "function") {
  window.showToast = (message, type = "success") => {
    let toast = document.getElementById("toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "toast";
      toast.style.position = "fixed";
      toast.style.bottom = "30px";
      toast.style.right = "30px";
      toast.style.padding = "12px 18px";
      toast.style.background = type === "error" ? "#ff6b6b" : "#00b894";
      toast.style.color = "#fff";
      toast.style.borderRadius = "8px";
      toast.style.zIndex = "1000";
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.display = "block";
    toast.style.background =
      type === "error" ? "#ff6b6b" : type === "warning" ? "#ffa502" : "#00b894";
    setTimeout(() => {
      toast.style.display = "none";
    }, 3000);
  };
}

if (typeof showLoading !== "function") {
  window.showLoading = () => {
    let overlay = document.getElementById("loadingOverlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "loadingOverlay";
      overlay.style.position = "fixed";
      overlay.style.top = "0";
      overlay.style.left = "0";
      overlay.style.right = "0";
      overlay.style.bottom = "0";
      overlay.style.background = "rgba(0,0,0,0.6)";
      overlay.style.display = "flex";
      overlay.style.alignItems = "center";
      overlay.style.justifyContent = "center";
      overlay.style.zIndex = "2000";

      const spinner = document.createElement("div");
      spinner.style.width = "50px";
      spinner.style.height = "50px";
      spinner.style.border = "4px solid rgba(255,255,255,0.3)";
      spinner.style.borderTopColor = "#fff";
      spinner.style.borderRadius = "50%";
      spinner.style.animation = "spin 0.8s linear infinite";

      const style = document.createElement("style");
      style.textContent = `
        @keyframes spin { to { transform: rotate(360deg); } }
      `;
      document.head.appendChild(style);

      overlay.appendChild(spinner);
      document.body.appendChild(overlay);
    }
    overlay.style.display = "flex";
  };
}

if (typeof hideLoading !== "function") {
  window.hideLoading = () => {
    const overlay = document.getElementById("loadingOverlay");
    if (overlay) overlay.style.display = "none";
  };
}

// ======= Crypto helpers =======

const SESSION_PASSWORD_KEY = "e2ee_session_password";

function getSessionPassword() {
  try {
    return sessionStorage.getItem(SESSION_PASSWORD_KEY) || "";
  } catch {
    return "";
  }
}

function setSessionPassword(pw) {
  try {
    sessionStorage.setItem(SESSION_PASSWORD_KEY, pw);
  } catch {
    // ignore
  }
}

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 120000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  return aesKey;
}

async function encryptFile(file, password) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const fileBuffer = await file.arrayBuffer();
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    fileBuffer
  );

  return { ciphertext, iv, salt };
}

async function decryptPayload(payload, password) {
  const salt = base64ToUint8Array(payload.salt);
  const iv = base64ToUint8Array(payload.iv);
  const ciphertext = base64ToUint8Array(payload.ciphertext).buffer;

  const key = await deriveKey(password, salt);
  const plaintext = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return new Uint8Array(plaintext);
}

// ======= Dashboard logic =======

document.addEventListener("DOMContentLoaded", () => {
  // ---- Upload encrypted file ----
  const uploadForm = document.getElementById("uploadForm");
  if (uploadForm) {
    const fileInput = document.getElementById("fileInput");
    const passwordInput = document.getElementById("encPassword");
    const currentPathInput = document.getElementById("currentPath");
    const fileNameLabel = document.getElementById("selectedFileName");

    if (fileInput && fileNameLabel) {
      fileInput.addEventListener("change", () => {
        if (fileInput.files.length) {
          fileNameLabel.textContent = fileInput.files[0].name;
        } else {
          fileNameLabel.textContent = "No file selected";
        }
      });
    }

    // pre-fill password from session if available
    const storedPw = getSessionPassword();
    if (storedPw && passwordInput && !passwordInput.value) {
      passwordInput.value = storedPw;
    }

    uploadForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!fileInput || !passwordInput) return;

      if (!fileInput.files.length) {
        showToast("Please select a file to upload.", "warning");
        return;
      }

      let password = passwordInput.value.trim();
      if (!password) {
        // maybe we have a stored password
        const saved = getSessionPassword();
        if (saved) {
          password = saved;
        } else {
          showToast("Please enter an encryption password.", "warning");
          return;
        }
      }

      const file = fileInput.files[0];

      try {
        showLoading();
        showToast("Encrypting file...", "success");

        const { ciphertext, iv, salt } = await encryptFile(file, password);

        const payload = {
          ciphertext: bufToBase64(ciphertext),
          iv: bufToBase64(iv),
          salt: bufToBase64(salt),
          filename: file.name,
          mimetype: file.type || "application/octet-stream",
        };

        const blob = new Blob([JSON.stringify(payload)], {
          type: "application/json",
        });

        const formData = new FormData();
        formData.append("file", blob, file.name + ".enc.json");
        formData.append("original_name", file.name);
        if (currentPathInput) {
          formData.append("current_path", currentPathInput.value || "");
        }

        const resp = await fetch("/upload", {
          method: "POST",
          body: formData,
        });

        const data = await resp.json();

        if (!resp.ok || !data.success) {
          console.error("Upload error:", data);
          showToast(data.message || "Upload failed", "error");
        } else {
          // remember password for this session
          setSessionPassword(password);
          showToast("Encrypted file uploaded successfully!", "success");
          setTimeout(() => window.location.reload(), 800);
        }
      } catch (err) {
        console.error("Encryption/upload error:", err);
        showToast("Error encrypting or uploading file.", "error");
      } finally {
        hideLoading();
      }
    });
  }

  // ---- Create folder (AJAX) ----
  const folderForm = document.getElementById("folderForm");
  if (folderForm) {
    folderForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const formData = new FormData(folderForm);
      try {
        showLoading();
        const resp = await fetch("/create_folder", {
          method: "POST",
          body: formData,
        });
        const data = await resp.json();
        if (!resp.ok || !data.success) {
          showToast(data.message || "Failed to create folder", "error");
        } else {
          showToast("Folder created", "success");
          setTimeout(() => window.location.reload(), 600);
        }
      } catch (err) {
        console.error(err);
        showToast("Network error while creating folder", "error");
      } finally {
        hideLoading();
      }
    });
  }

  // ---- Decrypt & download for owner ----
  document.querySelectorAll(".decrypt-download-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const filename = btn.dataset.filename;
      if (!filename) return;

      let password = getSessionPassword();
      if (!password) {
        password = prompt("Enter encryption password to decrypt:");
        if (!password) return;
      }

      try {
        showLoading();
        const resp = await fetch(
          `/download_encrypted/${encodeURIComponent(filename)}`
        );
        if (!resp.ok) {
          showToast("Failed to fetch encrypted file", "error");
          return;
        }
        const payload = await resp.json();
        const bytes = await decryptPayload(payload, password);

        // if decryption works, remember password
        setSessionPassword(password);

        const blob = new Blob([bytes], {
          type: payload.mimetype || "application/octet-stream",
        });

        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = payload.filename || "decrypted-file";
        document.body.appendChild(a);
        a.click();
        a.remove();

        showToast("File decrypted and downloaded", "success");
      } catch (err) {
        console.error("Decrypt error:", err);
        showToast(
          "Failed to decrypt. Check your password or try again.",
          "error"
        );
      } finally {
        hideLoading();
      }
    });
  });

  // ---- Delete file (AJAX with confirm) ----
  document.querySelectorAll(".delete-file-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const filename = btn.dataset.filename;
      if (!filename) return;

      const ok = confirm(`Delete "${filename}" permanently?`);
      if (!ok) return;

      try {
        showLoading();
        const resp = await fetch(`/delete/${encodeURIComponent(filename)}`, {
          method: "POST",
        });
        const data = await resp.json();
        if (!resp.ok || !data.success) {
          showToast(data.message || "Failed to delete file", "error");
        } else {
          showToast("File deleted", "success");
          setTimeout(() => window.location.reload(), 600);
        }
      } catch (err) {
        console.error("Delete error:", err);
        showToast("Network error while deleting file", "error");
      } finally {
        hideLoading();
      }
    });
  });

  // ---- Copy share link ----
  document.querySelectorAll(".copy-share-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const link = btn.dataset.shareUrl;
      if (!link) return;
      try {
        await navigator.clipboard.writeText(link);
        showToast("Share link copied to clipboard", "success");
      } catch (err) {
        console.error("Clipboard error:", err);
        showToast("Could not copy link", "error");
      }
    });
  });

  // ===== Shared file page decrypt =====
  const sharedBtn = document.getElementById("shared-decrypt-btn");
  if (sharedBtn) {
    sharedBtn.addEventListener("click", async () => {
      const ownerSafe = sharedBtn.dataset.ownerSafe;
      const filename = sharedBtn.dataset.filename;
      if (!ownerSafe || !filename) return;

      let password = getSessionPassword();
      if (!password) {
        password = prompt("Enter encryption password to decrypt this file:");
        if (!password) return;
      }

      try {
        showLoading();
        const resp = await fetch(
          `/shared_file/${encodeURIComponent(ownerSafe)}/${encodeURIComponent(
            filename
          )}`
        );
        if (!resp.ok) {
          showToast("Unable to fetch shared file", "error");
          return;
        }
        const payload = await resp.json();
        if (payload.error) {
          showToast(payload.error, "error");
          return;
        }

        const bytes = await decryptPayload(payload, password);
        setSessionPassword(password);

        const blob = new Blob([bytes], {
          type: payload.mimetype || "application/octet-stream",
        });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = payload.filename || "decrypted-file";
        document.body.appendChild(a);
        a.click();
        a.remove();

        showToast("File decrypted and downloaded", "success");
      } catch (err) {
        console.error("Shared decrypt error:", err);
        showToast("Failed to decrypt shared file", "error");
      } finally {
        hideLoading();
      }
    });
  }
});
