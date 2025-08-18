# Clean Database

A simple Flask-based lab database application for managing research data.  
This project is set up to be easy to install and run locally, with a build script (`run.ps1`) that handles environment setup and dependencies.

---

## Features
- Flask web application
- SQLAlchemy database integration
- User roles & login system (WIP)
- Auto environment setup via PowerShell script
- Dependency checklist with clear `[OK]` indicators

---

## Setup & Usage

### 1. Clone the Repository
```powershell
git clone https://github.com/WPSII/Clean-Database.git
cd Clean-Database
```

### 2. Run the Build Script
On **Windows (PowerShell):**
```powershell
.
un.ps1
```

The script will:
- Create a virtual environment (`venv/`) if not present
- Install dependencies from `requirements.txt`
- Show a checklist of installed packages
- Start the Flask app

### 3. Access the App
Once running, open your browser and go to:

👉 [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Example Output of `run.ps1`

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
- Do **not** commit `venv/`, `uploads/`, or `*.db` files. They are ignored via `.gitignore`.
- For a clean start:
```powershell
git rm -r --cached venv uploads *.db
git add .gitignore
git commit -m "Clean repo"
git push
```

---

## License
MIT License
