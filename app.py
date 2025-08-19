import os
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# --- Config ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "csv", "png", "jpg", "jpeg"}

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

    experiments = db.relationship(
        "Experiment", backref="project", cascade="all, delete-orphan"
    )
    samples = db.relationship(
        "Sample", backref="project", cascade="all, delete-orphan"
    )


class Experiment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    documents = db.relationship(
        "Document", backref="experiment", cascade="all, delete-orphan"
    )
    # via backref on SampleExperiment: experiment.sample_links -> [SampleExperiment]


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    experiment_id = db.Column(db.Integer, db.ForeignKey("experiment.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)     # original name
    stored_path = db.Column(db.String(500), nullable=False)  # absolute path on disk
    mimetype = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


# --- Sample models ---
class Sample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    # NEW:
    parent_id = db.Column(db.Integer, db.ForeignKey("sample.id"))  # nullable root
    parent = db.relationship("Sample",
                             remote_side=[id],
                             backref=db.backref("children", cascade="all, delete-orphan"))

    name = db.Column(db.String(160), nullable=False)
    manufacturer = db.Column(db.String(160))
    composition = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    documents = db.relationship("SampleDocument", backref="sample", cascade="all, delete-orphan")
    experiment_links = db.relationship("SampleExperiment", backref="sample", cascade="all, delete-orphan")


class SampleDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey("sample.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(500), nullable=False)
    mimetype = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class SampleExperiment(db.Model):
    """Many-to-many link: a Sample can be acted on by many Experiments (with a role)."""
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey("sample.id"), nullable=False)
    experiment_id = db.Column(db.Integer, db.ForeignKey("experiment.id"), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="other")  # irradiation, corrosion, polishing, other
    notes = db.Column(db.Text)

    experiment = db.relationship(
        "Experiment", backref=db.backref("sample_links", cascade="all, delete-orphan")
    )


# --- Helpers ---
def allowed_file(fn: str) -> bool:
    return "." in fn and fn.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def exp_upload_dir(project_id: int, experiment_id: int) -> str:
    d = os.path.join(UPLOAD_FOLDER, str(project_id), str(experiment_id))
    os.makedirs(d, exist_ok=True)
    return d


def sample_upload_dir(sample_id: int) -> str:
    d = os.path.join(UPLOAD_FOLDER, "samples", str(sample_id))
    os.makedirs(d, exist_ok=True)
    return d

def build_lineage(sample):
    chain = []
    cur = sample.parent
    while cur:
        chain.insert(0, cur)  # root → ... → parent
        cur = cur.parent
    return chain

# --- Routes ---
@app.route("/")
def index():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template("index.html", projects=projects)  # expects {{ projects }}


# ---- Projects ----
@app.route("/projects/create", methods=["POST"])
def create_project():
    title = request.form.get("title", "").strip()
    desc = request.form.get("description", "").strip()
    if not title:
        flash("Project title is required.", "error")
        return redirect(url_for("index"))
    project = Project(title=title, description=desc)
    db.session.add(project)
    db.session.commit()
    return redirect(url_for("view_project", project_id=project.id))


@app.route("/project/<int:project_id>")
def view_project(project_id):
    project = Project.query.get_or_404(project_id)
    # template should use {{ project }}, and can iterate project.experiments and each exp.sample_links
    return render_template("project.html", project=project)


@app.route("/project/<int:project_id>/experiments/create", methods=["POST"])
def create_experiment(project_id):
    project = Project.query.get_or_404(project_id)
    title = request.form.get("title", "").strip()
    desc = request.form.get("description", "").strip()
    if not title:
        flash("Experiment title is required.", "error")
        return redirect(url_for("view_project", project_id=project_id))
    experiment = Experiment(project=project, title=title, description=desc)
    db.session.add(experiment)
    db.session.commit()
    return redirect(url_for("view_experiment", experiment_id=experiment.id))


# ---- Experiments ----
@app.route("/experiment/<int:experiment_id>")
def view_experiment(experiment_id):
    experiment = Experiment.query.get_or_404(experiment_id)
    # template should use {{ experiment }}, access experiment.sample_links to list linked samples
    return render_template("experiment.html", experiment=experiment)


@app.route("/experiment/<int:experiment_id>/upload", methods=["POST"])
def upload_document(experiment_id):
    experiment = Experiment.query.get_or_404(experiment_id)
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("view_experiment", experiment_id=experiment.id))
    if not allowed_file(file.filename):
        flash("File type not allowed.", "error")
        return redirect(url_for("view_experiment", experiment_id=experiment.id))

    filename = secure_filename(file.filename)
    folder = exp_upload_dir(experiment.project_id, experiment.id)
    stored_path = os.path.join(folder, filename)

    # Avoid overwrite by appending counter
    base, ext = os.path.splitext(filename)
    i = 1
    while os.path.exists(stored_path):
        filename = f"{base}({i}){ext}"
        stored_path = os.path.join(folder, filename)
        i += 1

    file.save(stored_path)
    doc = Document(
        experiment=experiment,
        filename=file.filename,  # original
        stored_path=stored_path,
        mimetype=file.mimetype,
    )
    db.session.add(doc)
    db.session.commit()
    flash("File uploaded.", "ok")
    return redirect(url_for("view_experiment", experiment_id=experiment.id))


@app.route("/download/<int:doc_id>")
def download(doc_id):
    d = Document.query.get_or_404(doc_id)
    directory, name = os.path.dirname(d.stored_path), os.path.basename(d.stored_path)
    return send_from_directory(directory, name, as_attachment=True, download_name=d.filename)


# ---- Samples ----
@app.route("/samples")
def list_samples():
    q = request.args.get("q", "").strip()
    view = request.args.get("view", "project")  # default to project tree

    qry = Sample.query.order_by(Sample.created_at.desc())
    if q:
        like = f"%{q}%"
        qry = qry.filter(
            db.or_(
                Sample.name.ilike(like),
                Sample.manufacturer.ilike(like),
                Sample.composition.ilike(like),
            )
        )
    samples = qry.all()

    projects = Project.query.order_by(Project.title.asc()).all()

    # build roots per project for the tree view
    roots_by_project = {p.id: [s for s in p.samples if not s.parent_id] for p in projects}

    # options for dependent dropdowns
    experiment_opts = [
        {"id": e.id, "title": e.title, "project_id": e.project_id}
        for e in Experiment.query.order_by(Experiment.created_at.desc()).all()
    ]
    sample_opts = [
        {"id": s.id, "name": s.name, "project_id": s.project_id}
        for s in Sample.query.order_by(Sample.created_at.desc()).all()
    ]

    return render_template(
        "samples.html",
        samples=samples,
        projects=projects,
        roots_by_project=roots_by_project,
        experiment_opts=experiment_opts,
        sample_opts=sample_opts,
        q=q,
        view=view,
    )

@app.route("/samples/create", methods=["POST"])
def create_sample():
    # either project_id is chosen OR parent_id is chosen (parent wins)
    parent_id = request.form.get("parent_id", type=int)
    project_id = request.form.get("project_id", type=int)
    name = request.form.get("name","").strip()
    manufacturer = request.form.get("manufacturer","").strip()
    composition = request.form.get("composition","").strip()
    notes = request.form.get("notes","").strip()
    experiment_id = request.form.get("experiment_id", type=int)
    role = (request.form.get("role") or "other").strip().lower()

    parent = Sample.query.get(parent_id) if parent_id else None
    if parent:
        project_id = parent.project_id  # enforce same project as parent

    if not project_id or not name:
        flash("Project (or parent) and sample name are required.", "error")
        return redirect(url_for("list_samples"))

    sample = Sample(
        project_id=project_id,
        parent_id=parent.id if parent else None,
        name=name,
        manufacturer=manufacturer or (parent.manufacturer if parent else None),
        composition=composition or (parent.composition if parent else None),
        notes=notes,
    )
    db.session.add(sample); db.session.commit()

    if experiment_id:
        db.session.add(SampleExperiment(sample_id=sample.id, experiment_id=experiment_id, role=role))
        db.session.commit()

    flash("Sample created.", "ok")
    return redirect(url_for("view_sample", sample_id=sample.id))

@app.route("/sample/<int:sample_id>/split", methods=["POST"])
def split_sample(sample_id):
    parent = Sample.query.get_or_404(sample_id)
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Child sample name is required.", "error")
        return redirect(url_for("view_sample", sample_id=parent.id))

    manufacturer = request.form.get("manufacturer", parent.manufacturer)
    composition = request.form.get("composition", parent.composition)
    notes = request.form.get("notes","")

    child = Sample(
        project_id=parent.project_id,
        parent_id=parent.id,
        name=name,
        manufacturer=manufacturer,
        composition=composition,
        notes=notes
    )
    db.session.add(child); db.session.commit()
    flash("Child sample created.", "ok")
    return redirect(url_for("view_sample", sample_id=child.id))

@app.route("/sample/<int:sample_id>")
def view_sample(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    exp_choices = (Experiment.query
                   .filter_by(project_id=sample.project_id)
                   .order_by(Experiment.created_at.desc())
                   .all())
    lineage = build_lineage(sample)
    return render_template("sample.html", sample=sample, exp_choices=exp_choices, lineage=lineage)



@app.route("/sample/<int:sample_id>/link", methods=["POST"])
def link_experiment(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    experiment_id = request.form.get("experiment_id", type=int)
    role = (request.form.get("role") or "other").strip().lower()
    notes = request.form.get("notes", "").strip()

    if not experiment_id:
        flash("Please choose an experiment.", "error")
        return redirect(url_for("view_sample", sample_id=sample.id))

    # prevent duplicate link with same experiment & role
    existing = SampleExperiment.query.filter_by(
        sample_id=sample.id, experiment_id=experiment_id, role=role
    ).first()
    if existing:
        flash("Link already exists.", "error")
        return redirect(url_for("view_sample", sample_id=sample.id))

    link = SampleExperiment(
        sample_id=sample.id, experiment_id=experiment_id, role=role, notes=notes
    )
    db.session.add(link)
    db.session.commit()
    flash("Experiment linked.", "ok")
    return redirect(url_for("view_sample", sample_id=sample.id))


@app.route("/sample/link/<int:link_id>/delete", methods=["POST"])
def unlink_experiment(link_id):
    link = SampleExperiment.query.get_or_404(link_id)
    sid = link.sample_id
    db.session.delete(link)
    db.session.commit()
    flash("Link removed.", "ok")
    return redirect(url_for("view_sample", sample_id=sid))


@app.route("/sample/<int:sample_id>/upload", methods=["POST"])
def upload_sample_doc(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("view_sample", sample_id=sample.id))
    if not allowed_file(file.filename):
        flash("File type not allowed.", "error")
        return redirect(url_for("view_sample", sample_id=sample.id))

    safe_name = secure_filename(file.filename)
    folder = sample_upload_dir(sample.id)
    stored_path = os.path.join(folder, safe_name)

    base, ext = os.path.splitext(safe_name)
    i = 1
    while os.path.exists(stored_path):
        safe_name = f"{base}({i}){ext}"
        stored_path = os.path.join(folder, safe_name)
        i += 1

    file.save(stored_path)
    doc = SampleDocument(
        sample_id=sample.id, filename=file.filename, stored_path=stored_path, mimetype=file.mimetype
    )
    db.session.add(doc)
    db.session.commit()
    flash("Document uploaded.", "ok")
    return redirect(url_for("view_sample", sample_id=sample.id))


@app.route("/sample/doc/<int:doc_id>/download")
def download_sample_doc(doc_id):
    d = SampleDocument.query.get_or_404(doc_id)
    return send_from_directory(
        os.path.dirname(d.stored_path),
        os.path.basename(d.stored_path),
        as_attachment=True,
        download_name=d.filename,
    )


# --- Bootstrap DB on first run ---

with app.app_context():
    db.create_all()
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    cols = [c["name"] for c in insp.get_columns("sample")]
    if "parent_id" not in cols:
        # Adds column (FK constraint won’t be enforced by SQLite here, which is fine for dev)
        with db.engine.begin() as conn:
            conn.execute(text("ALTER TABLE sample ADD COLUMN parent_id INTEGER"))


if __name__ == "__main__":
    app.run(debug=True)
