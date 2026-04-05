# AI-For-Cyber-Defense
Project for intro to cybersecurity 
# How AI Can Aid in Cybersecurity

**Chosen Project Domain:** AI for Cyber Defense  
**Use Case:** AI-Based Phishing Detection and Explanation  

---

## 👥 Team Members and Roles

| Team Member | Assigned Role | Responsibilities |
| :--- | :--- | :--- |
| **Dylan Gibson** | Project Manager & Researcher | Coordinates deliverables, manages the GitHub repo, and researches current phishing trends. |
| **Quinten Shanks** | Lead Developer & AI Integration | Handles the technical implementation, prompt engineering, and core AI model integration. |
| **Sheyla Ramirez** | Security Analyst & QA | Defines security parameters, tests the AI's detection accuracy, and maps threat models. |
| **Caleb** | Data Engineer | Sources, cleans, and manages the datasets of benign and malicious emails used to test and tune the system. |
| **Rand** | Backend & Systems Integrator | Builds the parsing logic that extracts headers, links, and body text from emails to feed into the AI. |

---

## 🎯 Project Overview

### Project Objective
The primary objective of this project is to explore how Artificial Intelligence can be used defensively to identify phishing attempts. Unlike traditional spam filters that simply block emails, our system aims to detect malicious emails and provide a clear, AI-generated explanation to the end-user detailing *why* the email is dangerous, thereby improving user security awareness.

### Project Scope
Given the one-month timeline, this project will focus strictly on text-based and link-based email phishing analysis. 
* **In-Scope:** Analyzing email headers, body text, and URLs using an AI model to score the risk and generate an educational explanation.
* **Out-of-Scope:** Deploying a live enterprise-scale mail server interceptor, real-time attachment sandboxing, or training a foundational LLM from scratch.

### System Description
The proposed system acts as an analytical middle layer. When an email is received, its components (sender address, subject, body, links) are parsed and fed into a defensive AI model. The model evaluates the content for common phishing indicators (e.g., urgency, spoofed domains, unusual requests for PII). If flagged, the system outputs the original email alongside an "AI Explanation Report" that highlights the specific red flags for the user.

---

## 🛡️ Security Posture

### Initial Asset Inventory
The following assets are critical to our system and must be protected:

| Asset Category | Specific Asset | Justification |
| :--- | :--- | :--- |
| **Hardware/Infrastructure** | Development Computers & Servers | Required to host and run the detection pipeline. |
| **Data** | Training/Testing Datasets | Contains examples of phishing and benign emails used to tune the system. |
| **Data** | PII (Personally Identifiable Info) | May be present in the emails being analyzed; must not be leaked or stored improperly. |
| **AI Components** | LLM Prompts & Weights | The core logic of our defensive tool; if altered, the detection fails. |

### Initial Threat Assumptions
Based on our system design, we assume the following threats:
* **Adversarial Prompt Injection:** Attackers embedding hidden text in phishing emails designed to trick our AI into classifying the email as "Safe."
* **Data Exfiltration:** Unauthorized access to the email datasets being processed, potentially exposing sensitive PII.
* **Evasion Techniques:** Attackers using homoglyphs (e.g., replacing an English 'a' with a Cyrillic 'a') or image-only emails to bypass the AI's text analysis.
* **Model Poisoning:** (If fine-tuning) Malicious actors introducing flawed data into our training set to degrade detection accuracy.

---

## 📊 Diagrams and Architecture

### Use Case Diagram
*(Note to team: Upload the image file to the repository's root folder and link it here)* `![Use Case Diagram](./use-case-diagram.png)`

### System Overview
1. **User/System Input** -> Submits Email Data
2. **Parser** -> Extracts Text, Links, and Headers
3. **AI Analysis Engine** -> Scans for Malicious Intent
4. **Output Generator** -> Returns Risk Score + Explanation
5. **End User** -> Receives Educated Warning

---

## 🔗 Links
* **GitHub Repository:** [Insert Link Here]
* **Project Charter Submission:** [Insert Link Here]
