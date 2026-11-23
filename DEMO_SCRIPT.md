# PatchPilot demo script — 2:45

**Before recording (not on timer):** From the clone, install the requirements,
start `python -m patchpilot web` in a terminal, and open
`http://127.0.0.1:8765`. Make a clean copy of the fixture:

```sh
cp -R examples/vulnerable-app "$HOME/patchpilot-demo"
```

Use a previously unused destination. Keep the browser, editor, and terminal ready.

| Time | Exact action / what to show | Narration |
| --- | --- | --- |
| 0:00–0:20 | Show the browser landing page with the PatchPilot title and repository input. | “PatchPilot is my GenHacks project for the AI, Agentic Systems, Cybersecurity, and Dev Tools track. It reviews Python locally without running the code or sending it to a model.” |
| 0:20–0:43 | Paste `~/patchpilot-demo` into the input and click **Scan repository**. Show the severity totals. | “I can scan a public GitHub URL or a local folder. The analyzer reads Python syntax and reports ten real patterns in this deliberately flawed sample.” |
| 0:43–1:13 | Find **SQL injection**. Show the file and line, f-string, plain-language explanation, and the unified diff with the separate bound parameter. | “This SQLite query builds SQL from the user name. PatchPilot shows me where, explains the risk, and proposes a concrete change that passes the name separately as data.” |
| 1:13–1:45 | Click **Approve** on the SQL finding and pause on the approved badge. Then click **Apply approved patch**. Show the applied badge and the parameterized query in the editor. | “Approving changes review state, not the file. Applying is a separate action. The file now uses a bound parameter, and other findings have not been changed.” |
| 1:45–2:04 | Find **Weak cryptography** and click **Reject**. Show the rejected badge. Click **JSON report** and display the downloaded report. | “I can also reject an incompatible change. Both report formats include the evidence, proposed patch, and decision, so there’s a record of what I reviewed.” |
| 2:04–2:33 | In the clone's terminal run `python -m patchpilot scan examples/vulnerable-app` then `python -m patchpilot review`. Show the first finding prompt, then enter `q`. | “The same engine works on the command line. I can approve or reject each patch interactively, or quit without changing any files. The analysis and review require no API keys.” |
| 2:33–2:45 | Close on the successful UI result with the report links visible. | “PatchPilot makes risks actionable, but keeps the developer in control of every edit.” |
