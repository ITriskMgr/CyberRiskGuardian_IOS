# CyberRiskGuardian Mobile

An installable iPhone and iPad app for scenario-driven cybersecurity risk assessment with the CyberRiskGuardian (CRG) method. It runs full-screen from the Home Screen and works offline.

**Open the app:** https://itriskmgr.github.io/CyberRiskGuardian_IOS/

**User guide:** [USER_GUIDE.md](USER_GUIDE.md) — installation (with French iOS labels), every tab, Apple Intelligence setup, privacy and troubleshooting.

## Install on iPhone

1. Open the link above in **Safari**.
2. Tap **Share → Add to Home Screen**, then **Add**.
3. Open **CRG** from the Home Screen. After the first launch it works without a connection.

## What it does

| Tab | Purpose |
|---|---|
| **Risk** | CRG calculator: threat presence Pb(A), exploitation Pb(ψ,A), expected and maximum damage δe/δm, resilience θ, criticality μ(E), CVSS v4.0 and the treatment package (P, Q). Shows estimated, tolerated, mitigated and residual risk, the residual-to-tolerated ratio and its band, and the ±0.10 sensitivity cases. |
| **CVSS** | CVSS v4.0 base-score calculator. Build or paste a vector and apply it to the scenario. |
| **Register** | Saved scenarios, sorted by ratio, with counts above / at / below tolerance and totals. Exports JSON and CSV, imports JSON. |
| **Budget** | Appetite-consistent cybersecurity budget against the 4% / 7.8% / 12% of IT budget guideline, and a check of planned spend. |
| **Assistant** | Apple Intelligence through the Shortcuts app: scenario generation, explanations for management, treatment measures, key risk indicators and questions. |

The app opens with the fictional MediBec teaching case, marked as an example.

### Formulas

From the CyberRiskGuardian Excel Guide v1.0c, s.11, unchanged:

```
Estimated = Pb(A) × Pb(ψ,A) × CVSS × ((δe + δm) / 2) × μ(E) ÷ θ × Factor
Tolerated = Pb(A) × Pb(ψ,A) × CVSS × Appetite × μ(E) ÷ θ × Factor
Mitigated = Estimated × P × Q        Residual = Estimated − Mitigated
Ratio = Residual ÷ Tolerated   (< 0.90 below · 0.90–1.10 approximately at · > 1.10 above tolerance)
```

The JavaScript engines match the plugin's Python implementation: every CVSS v4.0 base vector (104,976) gives the same score as the Python `cvss` package, and the MediBec totals match `crg_calc.py`. Exported registers open directly in the [CyberRiskGuardian plugin](https://github.com/ITriskMgr/CyberRiskGuardian) (`crg_calc.py`, `build_workbook.py`).

## Apple Intelligence setup (once)

iOS gives Apple Intelligence to native apps and to the Shortcuts app, not to web apps, so the Assistant hands each request to a Shortcut.

1. In **Shortcuts**, create a shortcut named **CRG Assistant**.
2. Add **Use Model**. Choose **Private Cloud Compute** (better scenarios) or **On-Device** (nothing leaves the iPhone). Set the request to the **Shortcut Input** variable; if asked, receive **Text**.
3. Add **Copy to Clipboard** with the model's **Response**.
4. Add **Stop and Output** with the **Response**.
5. Optional: add **Show Notification** "Result copied. Return to CRG."
6. In the app, tap **Assistant → Test the Shortcut**.

Requires an iPhone with Apple Intelligence (iPhone 15 Pro or later), a recent iOS that includes the Use Model action, and Apple Intelligence turned on; availability depends on language and region. From the Home Screen app, return to CRG and tap **Paste result**. In a Safari tab, **Settings → Return automatically** brings the answer back through x-callback-url.

## Privacy

- Scenarios, settings and budget figures are stored only on the device (browser storage). Export the register regularly as a backup.
- The app makes no network requests after it is loaded, except opening the Shortcut you configured.
- Only the text of each Assistant request is passed to your Shortcut. Do not choose the ChatGPT extension model for confidential work, and leave names and confidential details out of the organization context.
- AI output is labelled "Analyst estimate — validation required" and never changes your numbers by itself.

## Files

| File | Role |
|---|---|
| `index.html`, `styles.css`, `app.js` | Interface |
| `crg.js` | CRG engine (mirrors `crg_calc.py`) |
| `cvss4.js` | CVSS v4.0 base score (port of the FIRST / Red Hat reference algorithm) |
| `sample.js` | Fictional MediBec example scenarios |
| `manifest.webmanifest`, `sw.js`, `icons/` | Home Screen install and offline cache |

To publish a copy: **Settings → Pages → Deploy from a branch → `main` / `(root)`**. When you change any file, raise `CACHE` in `sw.js` so installed copies update.

## Licence

© 2026 Marc-André Léger. Licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/); see `LICENSE` and `NOTICE.md`.

Quantitative results are relative decision-support indicators, not predictions of loss. Risk decisions remain with accountable management.
