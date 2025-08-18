import os
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# --- Config ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pdf","doc","docx","txt","csv","png","jpg","jpeg"}

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "lab.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024  # 256 MB

db = SQLAlchemy(app)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Models ---
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    experiments = db.relationship("Experiment", backref="project", cascade="all, delete-orphan")

class Experiment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    documents = db.relationship("Document", backref="experiment", cascade="all, delete-orphan")

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    experiment_id = db.Column(db.Integer, db.ForeignKey("experiment.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)       # original name
    stored_path = db.Column(db.String(500), nullable=False)    # absolute path on disk
    mimetype = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Helpers ---
def allowed_file(fn: str) -> bool:
    return "." in fn and fn.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def exp_upload_dir(project_id: int, experiment_id: int) -> str:
    d = os.path.join(UPLOAD_FOLDER, str(project_id), str(experiment_id))
    os.makedirs(d, exist_ok=True)
    return d

# --- Routes ---
@app.route("/")
def index():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template("index.html", projects=projects)

@app.route("/projects/create", methods=["POST"])
def create_project():
    title = request.form.get("title","").strip()
    desc = request.form.get("description","").strip()
    if not title:
        flash("Project title is required.","error")
        return redirect(url_for("index"))
    p = Project(title=title, description=desc)
    db.session.add(p); db.session.commit()
    return redirect(url_for("view_project", project_id=p.id))

@app.route("/project/<int:project_id>")
def view_project(project_id):
    p = Project.query.get_or_404(project_id)
    return render_template("project.html", p=p)

@app.route("/project/<int:project_id>/experiments/create", methods=["POST"])
def create_experiment(project_id):
    p = Project.query.get_or_404(project_id)
    title = request.form.get("title","").strip()
    desc = request.form.get("description","").strip()
    if not title:
        flash("Experiment title is required.","error")
        return redirect(url_for("view_project", project_id=project_id))
    e = Experiment(project=p, title=title, description=desc)
    db.session.add(e); db.session.commit()
    return redirect(url_for("view_experiment", experiment_id=e.id))

@app.route("/experiment/<int:experiment_id>")
def view_experiment(experiment_id):
    e = Experiment.query.get_or_404(experiment_id)
    return render_template("experiment.html", e=e)

@app.route("/experiment/<int:experiment_id>/upload", methods=["POST"])
def upload_document(experiment_id):
    e = Experiment.query.get_or_404(experiment_id)
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected.","error")
        return redirect(url_for("view_experiment", experiment_id=e.id))
    if not allowed_file(file.filename):
        flash("File type not allowed.","error")
        return redirect(url_for("view_experiment", experiment_id=e.id))

    filename = secure_filename(file.filename)
    folder = exp_upload_dir(e.project_id, e.id)
    stored_path = os.path.join(folder, filename)

    # avoid overwrite by appending counter
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(stored_path):
        filename = f"{base}({counter}){ext}"
        stored_path = os.path.join(folder, filename)
        counter += 1

    file.save(stored_path)

    doc = Document(experiment=e, filename=file.filename, stored_path=stored_path, mimetype=file.mimetype)
    db.session.add(doc); db.session.commit()
    flash("File uploaded.","ok")
    return redirect(url_for("view_experiment", experiment_id=e.id))

@app.route("/download/<int:doc_id>")
def download(doc_id):
    d = Document.query.get_or_404(doc_id)
    # send file from its experiment folder
    directory, name = os.path.dirname(d.stored_path), os.path.basename(d.stored_path)
    return send_from_directory(directory, name, as_attachment=True, download_name=d.filename)

# --- Bootstrap DB on first run ---
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
