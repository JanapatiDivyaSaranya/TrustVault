# 🛡️ TrustVault

**Zero-Trust Enterprise Multi-Tenant Document Management & Governance Portal**

TrustVault is a secure, lightweight enterprise document repository and governance web application built with **Python Flask**, **SQLAlchemy**, and **Tailwind CSS**. It provides robust administrative oversight through Role-Based Access Control (RBAC), granular file-level permission matrices, and real-time database audit telemetry logging.

---

## ✨ Key Features

* **🔐 Multi-Tier Role-Based Access Control (RBAC):**
  * **Admin:** Full governance authority with read, download, and delete access to all vault assets, plus global audit console telemetry.
  * **User (Standard User):** Personal document management and granular file-level permission delegation.
  * **Viewer:** Read-only role restricted strictly to explicitly shared vault assets.
* **⚡ Granular File-Level Access Matrices:** Administrators and document owners can configure custom read, write, and delete permissions per individual file.
* **📊 Visual Storage Quota Monitoring:** Tracks real-time storage consumption against system limits with dynamic progress indicators.
* **📋 Real-Time Database Audit Telemetry:** Automatically logs sensitive actions (authentication, uploads, downloads, deletions, permission changes) alongside client IP addresses.
* **🎨 Dynamic Multi-Theme Engine:** Seamlessly switch between **Emerald Governance**, **Graphite & Burnt Orange**, **Burgundy & Gold**, **Clean Light Mode**, and **Deep Dark Cyber**.
* **🔒 Strict Security Practices:** Interactive live password validation checklist with auto-ticking rules, unique username enforcement, and file-extension whitelisting.

---

## 🛠️ Technology Stack

* **Backend:** Python, Flask, Flask-Login, Flask-SQLAlchemy, Werkzeug Security
* **Database:** SQLite (with automatic `/tmp/` fallback for cloud environments like Render)
* **Frontend:** Jinja2 Templates, Tailwind CSS, JavaScript
* **Deployment:** Gunicorn, Render, Git/GitHub

---

## 🚀 How to Run Locally

Follow these exact steps to set up and run TrustVault on your local machine:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/trustvault.git](https://github.com/your-username/trustvault.git)
   cd trustvault
