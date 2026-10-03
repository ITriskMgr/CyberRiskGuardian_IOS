# CyberRiskGuardian Mobile — User Guide

October 2026 · Marc-André Léger

CyberRiskGuardian Mobile puts the CyberRiskGuardian (CRG) risk method on your iPhone: quantify a cybersecurity risk scenario, compare residual risk with your risk appetite, score a weakness with CVSS v4.0, keep a register and check your security budget. It installs from Safari, opens like an app and works offline.

**Open the app:** [itriskmgr.github.io/CyberRiskGuardian_IOS](https://itriskmgr.github.io/CyberRiskGuardian_IOS/)

## Contents

- [What the app does](#what-the-app-does)
- [Install on iPhone](#install-on-iphone)
- [Risk tab: quantify one scenario](#risk-tab-quantify-one-scenario)
- [CVSS tab: score the weakness](#cvss-tab-score-the-weakness)
- [Register tab: keep and share your scenarios](#register-tab-keep-and-share-your-scenarios)
- [Budget tab: match the budget to the appetite](#budget-tab-match-the-budget-to-the-appetite)
- [Assistant tab: Apple Intelligence (optional)](#assistant-tab-apple-intelligence-optional)
- [Settings](#settings)
- [Privacy and data](#privacy-and-data)
- [Troubleshooting](#troubleshooting)
- [Licence and credits](#licence-and-credits)

## What the app does

| Tab | Use it to |
| --- | --- |
| **Risk** | Enter one scenario's parameters and read its estimated, tolerated and residual risk, the residual ÷ tolerated ratio and its band |
| **CVSS** | Build or paste a CVSS v4.0 vector and get the base score |
| **Register** | Keep, compare, export and import your scenarios |
| **Budget** | Find the cybersecurity budget that matches your risk appetite (4% to 12% of the IT budget) |
| **Assistant** | Use Apple Intelligence to draft scenarios, explanations, treatments and indicators (optional) |

The app opens with the fictional **MediBec** teaching case so you can explore right away. Every example is labelled **Example**.

Three things to keep in mind:

- **Results are decision support.** The numbers are relative indicators for comparing and prioritizing risks, not predictions of loss. Validate estimates with the people who know the systems; risk decisions belong to management.
- **Your data stays on your phone.** Nothing is sent to a server. Export your register regularly as a backup.
- **AI is optional and never changes your numbers.** Anything the Assistant produces is marked "Analyst estimate — validation required".

## Install on iPhone

Installing takes under a minute and needs only Safari. Labels are shown as they appear on an English iPhone, with the French iOS label in brackets.

1. Open **Safari** and go to **itriskmgr.github.io/CyberRiskGuardian_IOS**.
2. Tap **Share** [**Partager**], the square with an arrow pointing up.
3. Scroll down and tap **Add to Home Screen** [**Sur l'écran d'accueil**].
4. Keep the name **CRG**. If you see **Open as Web App** [**Ouvrir en tant qu'app web**], leave it on. Tap **Add** [**Ajouter**].
5. Open **CRG** from your Home Screen. It runs full-screen, and works offline after this first launch.

The app also works on iPad, and in any desktop browser at the same address.

**Updates** arrive on their own: open the app while you're online, close it completely, then open it again.

**Moving to a new phone:** your data does not follow you. Export your register first (see Register), then import it on the new phone.

## Risk tab: quantify one scenario

The Risk tab turns one scenario's estimates into a single comparison with your risk appetite: the **residual ÷ tolerated ratio**, shown live at the top of the screen.

**1. Describe the scenario.** Give it a name and write the causal chain: threat source → weakness → affected asset or process → event → consequence. "Ransomware" alone is not a scenario.

**2. Set the six parameters** with the sliders or by typing a value from 0 to 1, for the next 12 months:

| Parameter | Symbol | Question it answers |
| --- | --- | --- |
| Threat presence | Pb(A) | How likely is the threat to be present? |
| Exploitation | Pb(ψ,A) | If present, how likely is it to exploit the weakness? |
| Expected damage | δe | How much harm is reasonably expected? |
| Maximum damage | δm | How much harm in a plausible worst case? Never below δe |
| Criticality | μ(E) | How important is the affected service to the mission? |
| Resilience | θ | How well can you prevent, detect, contain and recover? Higher is better |

**3. Add the technical severity.** Tap **Score the vector in CVSS** to build the CVSS v4.0 vector (next section), or type a **Manual score** from 0 to 10.

**4. Describe the treatment package.** **Probability reduction (P)** and **Impact reduction (Q)** are the expected effects of your planned measures, from 0 (none) to 1 (complete).

**5. Read the result.**

| Ratio | Band | What it means |
| --- | --- | --- |
| below 0.90 | **Below tolerance** (green) | Residual risk is within appetite |
| 0.90 to 1.10 | **At tolerance** (amber) | Residual risk is about at the limit |
| above 1.10 | **Above tolerance** (red) | Residual risk exceeds appetite: more treatment or a management decision is needed |

The gauge shows the ratio before treatment (hollow dot) and after (filled dot). Below it you'll find estimated, tolerated, mitigated and residual risk.

The **sensitivity** table moves every uncertain parameter by ±0.10. If the band changes between the lower and higher cases, validate those parameters before deciding.

**6. Save.** Tap **Save to register**. **New scenario** starts a blank one; opening a saved scenario and saving again updates it.

The formulas follow the CyberRiskGuardian Excel Guide v1.0c, s.11, unchanged:

```
Estimated = Pb(A) × Pb(ψ,A) × CVSS × ((δe + δm) / 2) × μ(E) ÷ θ × Factor
Tolerated = Pb(A) × Pb(ψ,A) × CVSS × Appetite × μ(E) ÷ θ × Factor
Mitigated = Estimated × P × Q        Residual = Estimated − Mitigated
Ratio     = Residual ÷ Tolerated
```

The ratio therefore depends only on average damage, P, Q and appetite; the other parameters set the size of the risk.

## CVSS tab: score the weakness

The CVSS tab gives the CVSS v4.0 base score of the weakness behind your scenario; the score then feeds the Risk calculation.

1. Pick one value for each of the 11 base metrics: **Exploitability** (AV, AC, AT, PR, UI), **Vulnerable system impact** (VC, VI, VA) and **Subsequent system impact** (SC, SI, SA). The score and severity update as you tap.
2. Or paste a complete vector, such as `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:L/SA:L`, into **Paste a vector**.
3. Tap **Use in scenario** to send it to the Risk tab, or **Copy vector** to use it elsewhere.

Scores follow the FIRST CVSS v4.0 specification (base metrics only) and match the reference implementation for every possible base vector. CVSS measures technical severity, not organizational risk: use it inside the CRG formula, never on its own. If a scenario has no identifiable technical weakness, say so and use a documented manual score.

## Register tab: keep and share your scenarios

The Register shows all saved scenarios at a glance, worst first, so you can see where residual risk exceeds appetite.

- **Summary:** how many scenarios are above, at and below tolerance; total estimated and residual risk; and the overall reduction from the planned treatments.
- **List:** each scenario with its ratio, band (colour stripe), residual risk and CVSS score. Tap one to open it in the Risk tab. Tags show **Example** (MediBec) and **✦ AI draft** (from the Assistant).
- **Export JSON:** the full register in the CyberRiskGuardian data model. It opens directly in the [CyberRiskGuardian plugin for Claude](https://github.com/ITriskMgr/CyberRiskGuardian) (`crg_calc.py`, `build_workbook.py`), so you can turn it into an Excel workbook and a report.
- **Export CSV:** one row per scenario with parameters and results, for Excel or Numbers.
- **Import JSON:** adds scenarios from a CyberRiskGuardian JSON file; the file's appetite, factor and currency are applied too.
- **Load MediBec example:** restores the 30 fictional teaching scenarios.
- **Clear register:** asks for confirmation, then deletes every scenario on this phone. Export first if you want to keep them.

On iPhone, exports open the share sheet: choose **Save to Files** [**Enregistrer dans Fichiers**], Mail, or AirDrop.

## Budget tab: match the budget to the appetite

The Budget tab gives the cybersecurity budget consistent with your risk appetite. The guideline is 4% to 12% of the total IT budget, salaries included.

| Position | Risk appetite | Share of IT budget |
| --- | --- | --- |
| Risk averse | 0.30 or lower | 12% |
| Risk neutral (median) | 0.50 | 7.8% |
| Risk seeking | 0.70 or higher | 4% |

Between those anchors the share changes in a straight line.

1. Enter the **Total IT budget** (salaries included) and set the **Risk appetite**.
2. Read the **appetite-consistent budget**, the amount and the percentage, with the 4%, 7.8% and 12% amounts below it.
3. Optionally enter **planned cybersecurity spend** for up to three years. Each year shows its share of the IT budget, whether it is within the band, and the risk appetite that spend implies.

A year that implies a higher appetite than the one you set is a signal: either the budget or the stated appetite needs a management decision.

## Assistant tab: Apple Intelligence (optional)

The Assistant uses Apple Intelligence to draft scenarios, explain a result for management, suggest treatment measures, propose key risk indicators and answer questions. Everything else in the app works without it.

**Requirements:** an iPhone with Apple Intelligence (iPhone 15 Pro, iPhone 16 or later), a current iOS, and Apple Intelligence turned on. Apple Intelligence only appears when the **iPhone language** and **Siri language** are the same supported language, for example both *Français (Canada)*.

### One-time setup: the CRG Assistant shortcut

iOS gives Apple Intelligence to the Shortcuts app, not to web apps, so CRG hands each request to a shortcut you create once.

1. Open **Shortcuts** [**Raccourcis**], tap **+**, and name the shortcut **CRG Assistant**, exactly.
2. Add the **Use Model** action [search **modèle**]. Choose **Private Cloud Compute** for better results or **On-Device** [**Sur l'appareil**] to keep everything on the iPhone. Don't choose ChatGPT for confidential work.
3. In the request field, insert the **Shortcut Input** variable [**Entrée du raccourci**]. If asked what to receive, choose **Text** [**Texte**].
4. Add **Copy to Clipboard** [**Copier dans le presse-papiers**] with the model's **Response** [**Réponse**].
5. Add **Stop and Output** [search **sortie**] with the **Response**.
6. Optional: add **Show Notification** [**Afficher une notification**]: "Result copied. Return to CRG."
7. In CRG, tap **Assistant → Test the Shortcut**, return to CRG and tap **Paste result**. You should see "Shortcut works".

French action names may be worded slightly differently on your iOS version; searching for the bracketed word finds them.

### Using it

1. Choose a task: **Generate scenarios** (describe the organization first), **Explain the result for management**, **Suggest treatment measures**, **Propose key risk indicators**, or **Ask**.
2. iOS opens Shortcuts and runs the model. Allow CRG to open Shortcuts if asked.
3. Return to CRG and tap **Paste result** (allow pasting if asked), or paste into the box.
4. Generated scenarios can be added to the register as **AI drafts**. Score each draft's own CVSS vector and set its treatment package before relying on it.

For answers in French, open **Settings** (gear icon) and set **Response language** to **Français**. Leave names and confidential details out of the organization description.

## Settings

Tap the gear icon on any tab.

| Setting | Default | What it changes |
| --- | --- | --- |
| Risk appetite | 0.30 | Tolerance for every scenario and the budget target (0.1–0.2 very risk averse, 0.3 low, 0.5 neutral, 0.7 high) |
| Factor | 1,000 | Scale of the risk values; keep it constant across scenarios |
| Currency | CAD | Currency of budget amounts |
| Shortcut name | CRG Assistant | Must match the shortcut you created |
| Response language | English | Language of Assistant answers |
| Return automatically | Off | In a Safari tab only, brings the Assistant answer back without pasting |

## Privacy and data

- Scenarios, settings and budget figures are stored only in the app on your iPhone. There is no account and no server.
- The app makes no network requests after it loads, except opening your shortcut.
- With the Assistant, only the text of each request goes to your shortcut. On-Device keeps it on the iPhone; Private Cloud Compute processes it on Apple servers without keeping it.
- Follow your organization's rules before entering confidential, personal or regulated information, especially in the Assistant.
- Clearing Safari website data can delete the register. Export it regularly.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| The address shows a 404 page | Check the spelling; the site may take a few minutes to publish after an update |
| No **Add to Home Screen** option | Use Safari; scroll down in the Share sheet, or tap **Edit Actions** [**Modifier les actions**] |
| My scenarios disappeared | Website data was cleared or the phone changed; import your last JSON export |
| No **Apple Intelligence & Siri** [**Apple Intelligence et Siri**] in Settings [**Réglages**] | Update iOS; set the iPhone language and the Siri language to the same language; free storage; check Screen Time [**Temps d'écran**] restrictions and any work profile under **VPN & Device Management** [**VPN et gestion de l'appareil**] |
| No **Use Model** action in Shortcuts | Apple Intelligence is not turned on or not finished downloading; keep the iPhone on Wi-Fi and charging |
| Tapping an Assistant button does nothing | The shortcut name must match **Settings → Shortcut name** exactly |
| **Paste result** says it can't read the clipboard | Allow pasting when iOS asks, or paste into the box under the button |
| Generated scenarios show as plain text | The answer wasn't in the expected format; run it again or switch the shortcut to Private Cloud Compute |

## Licence and credits

CyberRiskGuardian and CyberRiskGuardian Mobile © 2026 Marc-André Léger, licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/): share and adapt for non-commercial purposes with attribution. CVSS v4.0 scoring tables © FIRST.ORG, Inc., Red Hat and contributors (BSD licence). CVSS is a trademark of FIRST; Apple Intelligence and Shortcuts are trademarks of Apple Inc. The app is not affiliated with FIRST or Apple. MediBec is a fictional teaching case.

- App: [github.com/ITriskMgr/CyberRiskGuardian_IOS](https://github.com/ITriskMgr/CyberRiskGuardian_IOS)
- Claude plugin and methodology: [github.com/ITriskMgr/CyberRiskGuardian](https://github.com/ITriskMgr/CyberRiskGuardian)
