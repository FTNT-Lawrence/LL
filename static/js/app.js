/* FortiSIEM Parser Generator — frontend wizard */
(function () {
  "use strict";

  const state = {
    step: 1,
    logText: "",
    detection: null,
    commonAttrs: [],
    generate: null,
    fileName: null,
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const SAMPLES = {
    cisco: `<190>91809: Jan 9 02:38:47.872: %SEC-6-IPACCESSLOGP: list testlog permitted tcp 192.168.20.33(3438) -> 69.147.86.184(80), 1 packet
<186>91810: Jan 9 02:39:01.120: %SEC-6-IPACCESSLOGP: list testlog denied udp 10.1.1.5(53122) -> 8.8.8.8(53), 1 packet
<190>91811: Jan 9 02:40:15.440: %SEC-6-IPACCESSLOGP: list dmz-in permitted tcp 172.16.0.10(443) -> 192.168.1.50(51234), 3 packets`,
    kv: `timestamp=2024-03-15T10:22:01Z src=10.0.0.15 dst=203.0.113.50 sport=54321 dport=443 proto=tcp action=allow user=alice bytes=4096
timestamp=2024-03-15T10:22:05Z src=10.0.0.22 dst=198.51.100.8 sport=49812 dport=80 proto=tcp action=deny user=bob bytes=0
timestamp=2024-03-15T10:22:09Z src=10.0.1.9 dst=203.0.113.10 sport=22001 dport=22 proto=tcp action=allow user=carol bytes=1024`,
    csv: `timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,user,bytes
2024-03-15 10:22:01,10.0.0.15,203.0.113.50,54321,443,tcp,allow,alice,4096
2024-03-15 10:22:05,10.0.0.22,198.51.100.8,49812,80,tcp,deny,bob,0
2024-03-15 10:22:09,10.0.1.9,203.0.113.10,22001,22,tcp,allow,carol,1024`,
  };

  // ——— Theme ———
  const themeToggle = $("#themeToggle");
  const savedTheme = localStorage.getItem("fspg-theme");
  if (savedTheme) document.documentElement.setAttribute("data-theme", savedTheme);
  themeToggle?.addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("fspg-theme", next);
  });

  // ——— Stepper ———
  function goTo(step) {
    state.step = step;
    $$(".panel").forEach((p) => p.classList.remove("active"));
    $(`#panel${step}`)?.classList.add("active");
    $$(".step").forEach((btn) => {
      const n = Number(btn.dataset.step);
      btn.classList.toggle("active", n === step);
      btn.classList.toggle("done", n < step);
      if (n <= maxUnlocked()) btn.disabled = false;
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function maxUnlocked() {
    if (state.generate) return 4;
    if (state.detection) return 3;
    if (state.logText.trim()) return 2;
    return 1;
  }

  $$(".step").forEach((btn) => {
    btn.addEventListener("click", () => {
      const n = Number(btn.dataset.step);
      if (n <= maxUnlocked()) goTo(n);
    });
  });

  $$("[data-goto]").forEach((btn) => {
    btn.addEventListener("click", () => goTo(Number(btn.dataset.goto)));
  });

  // ——— Dropzone ———
  const dropzone = $("#dropzone");
  const fileInput = $("#fileInput");
  const logText = $("#logText");

  function setFileChip(name) {
    const chip = $("#fileChip");
    if (!name) {
      chip.hidden = true;
      chip.innerHTML = "";
      return;
    }
    chip.hidden = false;
    chip.innerHTML = `<span class="file-chip">📄 ${escapeHtml(name)}</span>`;
  }

  async function readFile(file) {
    const text = await file.text();
    logText.value = text;
    state.logText = text;
    state.fileName = file.name;
    setFileChip(file.name);
  }

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    const f = e.dataTransfer.files?.[0];
    if (f) readFile(f);
  });
  fileInput.addEventListener("change", () => {
    const f = fileInput.files?.[0];
    if (f) readFile(f);
  });

  $$("[data-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.dataset.sample;
      logText.value = SAMPLES[key] || "";
      state.logText = logText.value;
      state.fileName = `sample-${key}.log`;
      setFileChip(state.fileName);
    });
  });

  // ——— Detect ———
  $("#btnDetect").addEventListener("click", async () => {
    const text = logText.value.trim();
    if (!text) {
      toast("Please paste or upload sample logs first.", true);
      return;
    }
    state.logText = text;
    const btn = $("#btnDetect");
    setLoading(btn, true);
    try {
      const res = await fetch("/api/detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          log_text: text,
          vendor: $("#vendor").value,
          model: $("#model").value,
          parser_name: $("#parserName").value,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      state.detection = data;
      state.commonAttrs = data.common_attributes || [];
      renderFormatChips();
      suggestMetaFromFormat(data);
      goTo(2);
      toast(`Detected ${data.format} (${Math.round(data.confidence * 100)}% confidence)`);
    } catch (err) {
      toast(String(err.message || err), true);
    } finally {
      setLoading(btn, false, "Detect format & continue");
    }
  });

  function suggestMetaFromFormat(data) {
    if (!$("#parserName").value) {
      const fmt = (data.format || "Custom").replace(/_/g, "");
      $("#parserName").value = `${($("#vendor").value || "Generic").replace(/\s/g, "")}${fmt}Parser`;
    }
  }

  function renderFormatChips() {
    const d = state.detection;
    if (!d) return;
    const html = `
      <span class="chip accent"><span class="dot"></span>${escapeHtml(d.format)}</span>
      <span class="chip ${d.confidence >= 0.7 ? "ok" : "warn"}">${Math.round(d.confidence * 100)}% confidence</span>
      <span class="chip info">${d.fields.length} fields</span>
    `;
    $("#formatChips").innerHTML = html;
    $("#formatChips2").innerHTML = html;
  }

  $("#btnToMap").addEventListener("click", () => {
    if (!$("#vendor").value.trim() || !$("#model").value.trim()) {
      toast("Vendor and Model are required.", true);
      return;
    }
    if (!$("#parserName").value.trim()) {
      $("#parserName").value = `${$("#vendor").value}${$("#model").value}Parser`.replace(/\s/g, "");
    }
    renderMappingTable();
    goTo(3);
  });

  function renderMappingTable() {
    const d = state.detection;
    const body = $("#mappingBody");
    if (!d || !d.fields.length) {
      $("#mappingEmpty").hidden = false;
      $("#mappingWrap").hidden = true;
      return;
    }
    $("#mappingEmpty").hidden = true;
    $("#mappingWrap").hidden = false;

    const opts = ['<option value="">— skip —</option>']
      .concat(state.commonAttrs.map((a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`))
      .join("");

    body.innerHTML = d.fields
      .map((f, i) => {
        const samples = (f.sample_values || []).slice(0, 3).join(", ");
        const suggested = f.suggested_attr || "";
        return `<tr data-idx="${i}">
          <td><span class="field-name">${escapeHtml(f.name)}</span>
            ${f.position != null ? `<div style="color:var(--text-dim);font-size:0.72rem">pos ${f.position}</div>` : ""}
          </td>
          <td><div class="samples" title="${escapeHtml(samples)}">${escapeHtml(samples) || "—"}</div></td>
          <td>
            <select class="map-select" data-idx="${i}">
              ${opts}
            </select>
            <input type="text" class="map-custom" data-idx="${i}" placeholder="or custom attr…"
              style="margin-top:6px;width:100%;height:32px;border-radius:8px;border:1px solid var(--border);background:var(--bg-input);color:var(--text);padding:0 8px;font:inherit;font-size:0.82rem" />
          </td>
        </tr>`;
      })
      .join("");

    body.querySelectorAll(".map-select").forEach((sel) => {
      const idx = Number(sel.dataset.idx);
      const suggested = d.fields[idx].suggested_attr || "";
      if (suggested) sel.value = suggested;
      sel.addEventListener("change", () => {
        const custom = body.querySelector(`.map-custom[data-idx="${idx}"]`);
        if (sel.value && custom) custom.value = "";
      });
    });
  }

  function collectMappings() {
    const d = state.detection;
    if (!d) return [];
    return d.fields.map((f, i) => {
      const sel = $(`.map-select[data-idx="${i}"]`);
      const custom = $(`.map-custom[data-idx="${i}"]`);
      let attr = (custom && custom.value.trim()) || (sel && sel.value) || "";
      return {
        field_name: f.name,
        forti_attr: attr,
        position: f.position ?? null,
        key: f.key ?? f.name,
        sample_values: f.sample_values || [],
      };
    });
  }

  // ——— Generate ———
  $("#btnGenerate").addEventListener("click", async () => {
    const btn = $("#btnGenerate");
    setLoading(btn, true);
    try {
      const payload = {
        log_text: state.logText,
        parser_name: $("#parserName").value.trim(),
        vendor: $("#vendor").value.trim(),
        model: $("#model").value.trim(),
        version: $("#version").value.trim() || "ANY",
        app_vendor: $("#appVendor").value.trim() || null,
        app_model: $("#appModel").value.trim() || null,
        mappings: collectMappings(),
      };
      const res = await fetch("/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      state.generate = data;
      renderPreview(data);
      goTo(4);
      toast("Parser XML generated");
    } catch (err) {
      toast(String(err.message || err), true);
    } finally {
      setLoading(btn, false, "Generate parser XML");
    }
  });

  function renderPreview(data) {
    $("#xmlPreview").innerHTML = highlightXml(data.xml || "");
    $("#resultChips").innerHTML = `
      <span class="chip accent"><span class="dot"></span>${escapeHtml(data.format)}</span>
      <span class="chip ok">${escapeHtml(data.parser_name || "parser")}</span>
      ${
        data.custom_attributes?.length
          ? `<span class="chip warn">${data.custom_attributes.length} custom attr(s)</span>`
          : ""
      }
    `;

    const dryBody = $("#dryBody");
    if (!data.dry_run?.length) {
      dryBody.innerHTML = `<tr><td colspan="2" class="empty-state">No dry-run rows</td></tr>`;
    } else {
      dryBody.innerHTML = data.dry_run
        .map((row) => {
          const pills = Object.entries(row.attrs || {})
            .filter(([k]) => !k.startsWith("_") || k === "_note")
            .map(
              ([k, v]) =>
                `<span class="attr-pill"><b>${escapeHtml(k)}</b>=${escapeHtml(String(v))}</span>`
            )
            .join("");
          return `<tr>
            <td><div class="dry-raw" title="${escapeHtml(row.raw)}">${escapeHtml(row.raw)}</div></td>
            <td><div class="attr-pills">${pills || "—"}</div></td>
          </tr>`;
        })
        .join("");
    }

    const notes = $("#notesList");
    const items = [...(data.notes || [])];
    if (data.custom_attributes?.length) {
      items.unshift(
        "Create these Event Attributes in FortiSIEM if missing: " +
          data.custom_attributes.join(", ")
      );
    }
    notes.innerHTML = items.map((n) => `<li>${escapeHtml(n)}</li>`).join("") || "<li>No extra notes.</li>";
  }

  $("#btnCopy").addEventListener("click", async () => {
    if (!state.generate?.xml) return;
    try {
      await navigator.clipboard.writeText(state.generate.xml);
      toast("XML copied to clipboard");
    } catch {
      toast("Clipboard unavailable — select and copy from the preview.", true);
    }
  });

  $("#btnDownload").addEventListener("click", async () => {
    if (!state.generate) return;
    const payload = {
      log_text: state.logText,
      parser_name: $("#parserName").value.trim(),
      vendor: $("#vendor").value.trim(),
      model: $("#model").value.trim(),
      version: $("#version").value.trim() || "ANY",
      app_vendor: $("#appVendor").value.trim() || null,
      app_model: $("#appModel").value.trim() || null,
      mappings: collectMappings(),
    };
    const res = await fetch("/api/download", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      toast("Download failed", true);
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.generate.parser_name || "CustomParser"}.xml`;
    a.click();
    URL.revokeObjectURL(url);
    toast("Download started");
  });

  // ——— Helpers ———
  function setLoading(btn, on, label) {
    if (!btn) return;
    if (on) {
      btn.disabled = true;
      btn.dataset.label = btn.textContent;
      btn.innerHTML = `<span class="loading"></span> Working…`;
    } else {
      btn.disabled = false;
      btn.textContent = label || btn.dataset.label || "Continue";
    }
  }

  function toast(msg, isError) {
    $$(".toast").forEach((t) => t.remove());
    const el = document.createElement("div");
    el.className = "toast" + (isError ? " error" : "");
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 3200);
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function highlightXml(xml) {
    // Lightweight token highlighter (escaped output)
    let s = escapeHtml(xml);
    s = s.replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="t-cmt">$1</span>');
    s = s.replace(
      /(&lt;\/?)([\w:-]+)([^&]*?)(\/?&gt;)/g,
      (_, open, name, attrs, close) => {
        const attrHtml = attrs.replace(
          /([\w:-]+)=(&quot;[\s\S]*?&quot;)/g,
          '<span class="t-attr">$1</span>=<span class="t-str">$2</span>'
        );
        return `<span class="t-punct">${open}</span><span class="t-name">${name}</span>${attrHtml}<span class="t-punct">${close}</span>`;
      }
    );
    return s;
  }
})();
