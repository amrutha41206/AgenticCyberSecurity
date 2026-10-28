# 🛡️ Agentic AI Cybersecurity Platform for Malware Analysis and Threat Detection

## 1. Project Overview

The **Agentic AI Cybersecurity Platform for Malware Analysis and Threat Detection** is an academic cybersecurity prototype that analyzes files and security alerts to identify potentially suspicious indicators and generate preliminary investigation reports.

The platform combines Python-based static analysis, a conditional LangGraph workflow, local threat-indicator lookup, and a locally hosted Large Language Model (LLM). A Streamlit dashboard provides an interface for reviewing findings, risk assessments, and recommended defensive actions.

The system is designed to assist preliminary security investigations without executing uploaded files.

## 2. Problem Statement

Security analysts often need to inspect suspicious files, review security alerts, identify indicators, and determine which investigation steps to perform next.

Manual investigation can require several separate tools and repetitive analysis.

This project aims to provide a unified prototype that automates selected analysis tasks, organizes findings, and recommends follow-up checks through a structured workflow.

## 3. Objectives

- Perform static analysis of uploaded files without executing them.
- Extract potentially relevant indicators, including URLs, IP addresses, and domains.
- Analyze user-provided security alert text.
- Compare extracted indicators against a local demonstration threat-intelligence dataset.
- Coordinate analysis steps using LangGraph.
- Generate structured findings and defensive recommendations.
- Use a local LLM to provide supplementary explanations.
- Present investigation results through an interactive Streamlit dashboard.

## 4. Key Features

### Static File Analysis
- File metadata and size analysis.
- SHA-256 hash calculation.
- Entropy measurement.
- File-type and available PE metadata inspection.
- Extraction of readable strings and potential indicators.

### Security Alert Analysis
- Accepts security alert or log text.
- Extracts candidate IP addresses and domains.
- Passes extracted indicators to the threat-lookup workflow.

### Threat Intelligence Lookup
- Compares extracted indicators against a local JSON dataset.
- Reports matched and unmatched indicators.
- Distinguishes demonstration labels such as `known_malicious`, `suspicious`, and `known_benign`.

### Investigation Agent
- Summarizes findings from the supplied investigation results.
- Identifies follow-up checks.
- Reports matched indicators, unmatched indicators, and processing errors.

### AI-Assisted Reporting
- Uses a locally hosted language model to generate supplementary explanations.
- Combines the explanation with rule-based results and structured investigation data.
- Keeps the limitations of AI-generated conclusions visible.

### Streamlit Dashboard
- Provides separate file-analysis and alert-analysis modes.
- Displays risk assessments, file properties, indicators, findings, and recommendations.
- Includes processing warnings and a detailed JSON report.

## 5. System Architecture

The application follows a modular architecture.

```text
                 User
                  |
                  v
          Streamlit Dashboard
                  |
                  v
           LangGraph Workflow
                  |
          +-------+-------+
          |               |
          v               v
     File Analysis    Alert Analysis
          |               |
          +-------+-------+
                  |
                  v
        Indicator Extraction
                  |
                  v
       Local Threat Intelligence
                  |
                  v
         Investigation Agent
                  |
          +-------+-------+
          |               |
          v               v
     Rule-Based       Local LLM
     Assessment      Explanation
          |               |
          +-------+-------+
                  |
                  v
          Investigation Report
                  |
                  v
           Streamlit Dashboard
```

The diagram represents the high-level workflow. The actual execution order depends on the implemented graph and its routing logic.

## 6. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic and analysis |
| Streamlit | Interactive dashboard |
| LangGraph | Workflow orchestration and conditional routing |
| Ollama | Local language-model runtime |
| Qwen2.5 1.5B | Local LLM used for supplementary explanations |
| Pandas | Tabular presentation of investigation results |
| JSON | Local threat-indicator storage and structured reports |
| Pytest | Automated testing |

## 7. Project Structure

```text
AgenticCyberSecurity/
├── agents/
│   ├── static_analysis.py
│   ├── alert_analysis.py
│   ├── threat_intelligence.py
│   ├── investigation_agent.py
│   └── local_llm.py
├── core/
│   └── graph.py
├── data/
│   └── threat_indicators.json
├── tests/
│   └── test_*.py
├── app.py
├── requirements.txt
└── README.md
```

This is a high-level representation of the project structure. Keep the filenames aligned with the files actually present in your repository.

## 8. Installation and Setup

### Prerequisites

- Python installed on your computer.
- Git, if cloning the repository.
- Ollama installed for local LLM functionality.
- The required Python dependencies.

### Step 1: Clone the Repository

```bash
git clone https://github.com/amrutha41206/AgenticCyberSecurity.git
cd AgenticCyberSecurity
```

If your repository uses a different name or URL, replace the command with the correct repository URL.

### Step 2: Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### Step 4: Prepare the Local LLM

Install Ollama if it is not already installed, then download the configured model:

```bash
ollama pull qwen2.5:1.5b
```

Ensure the Ollama service is running before testing AI-generated explanations.

### Step 5: Run the Application

```bash
streamlit run app.py
```

Open the local URL displayed in the terminal.

## 9. Running Tests

Activate the project virtual environment and execute:

```bash
python -m pytest -v
```

**Current validation result:** 22 tests passed in the project's reported test run.

This result describes the tests run at that point in development. Run the tests again after making further changes.

## 10. Example Demonstration

The project includes synthetic demonstration indicators for testing the investigation workflow.

An example security alert is:

```text
Suspicious connection to malware-example.test
from 203.0.113.10
```

The platform extracts candidate indicators, compares them against the local dataset, and generates a structured report containing findings and follow-up checks.

The example uses synthetic data and reserved documentation addresses. It is not evidence of an actual malware infection or malicious network activity.

## 11. Limitations

- The local threat-intelligence dataset contains synthetic demonstration entries.
- A match against a demonstration entry does not independently establish malicious activity.
- An unmatched indicator does not establish that a file or host is safe.
- Static analysis cannot reliably identify every form of malware.
- AI-generated explanations may be inaccurate and require verification.
- The investigation agent currently uses deterministic Python rules; it is not a fully autonomous security analyst.
- The prototype does not replace professional endpoint detection, sandboxing, or incident-response systems.
- The project does not establish real-world detection accuracy without evaluation against an appropriate labelled dataset.

## 12. Future Enhancements

Potential future improvements include:

- Integration with trusted threat-intelligence services.
- Evaluation against a labelled malware-analysis dataset in a controlled environment.
- More detailed audit logs and investigation history.
- Improved workflow routing based on available evidence.
- Explainability and confidence calibration for investigation results.
- Additional unit and integration tests.

These are potential enhancements and are not claims about currently implemented features.

## 13. Security and Responsible Use

- Uploaded files are intended for static inspection, not execution.
- Do not upload confidential or sensitive files.
- Treat generated risk assessments as preliminary.
- Validate findings using trusted security tools and sources.
- Keep investigation actions under human review.

## 14. Conclusion

The Agentic AI Cybersecurity Platform demonstrates how static analysis, structured Python rules, local threat-indicator lookup, LangGraph workflow orchestration, and a local language model can be combined into a cybersecurity investigation prototype.

The project provides a modular foundation for examining suspicious files and security alerts, organizing findings, and recommending follow-up investigation steps.

**Project status:** Academic prototype with a working Streamlit interface and a reported 22 passing automated tests.
