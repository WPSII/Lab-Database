
# Clean Database

Clean Database is a simple, local-first Flask web app for managing research data in a lab setting. It’s designed for easy setup and use, with a PowerShell build script (`run.ps1`) that handles everything from environment creation to dependency checks and app launch.

---

## Features

- Modern Flask web interface
- SQLAlchemy ORM for database management
- User roles & login system (work in progress)
- One-command setup via PowerShell (`run.ps1`)
- Dependency checklist with clear [OK] indicators

---

## Quick Start

### 1. Clone the Repository

```powershell
git clone https://github.com/WPSII/rickBASE.git
cd rickBASE
```

### 2. Run the Build Script

On Windows (PowerShell):

```powershell
.
run.ps1
```

What the script does:
- Creates a virtual environment (`venv/`) if missing
- Installs all dependencies from `requirements.txt`
- Checks and lists all required packages
- Starts the Flask app automatically

### 3. Open the App

Once running, visit:

👉 http://127.0.0.1:5000

---

## Example Output (`run.ps1`)

```
Virtual environment found at 'venv'.
Upgrading pip (quiet)...
Checking dependencies...
[OK] Flask==3.1.1
[OK] SQLAlchemy==2.0.42
[OK] Werkzeug==3.1.3
...etc...
Starting app: venv\Scripts\python.exe app.py --host=127.0.0.1 --port=5000
 * Running on http://127.0.0.1:5000
```

---

## Development Notes

- Do **not** commit `venv/`, `uploads/`, or `*.db` files. These are ignored via `.gitignore`.
- For a clean repo:
	```powershell
	git rm -r --cached venv uploads *.db
	git add .gitignore
	git commit -m "Clean repo"
	git push
	```

---

## License

Copyright © 2026 Patrick Simon. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, modification, or use of this software, in whole or in part, is strictly prohibited without express written permission from the copyright holder.
