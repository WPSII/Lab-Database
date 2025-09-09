import os
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask import jsonify
import json
import qrcode
import io
from flask import send_file, session
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

def _uid():
    return current_user.id if getattr(current_user, "is_authenticated", False) else None


# --- Config ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "csv", "png", "jpg", "jpeg"}

app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = "auth_login"  # where to send non-authed users

@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))

app.config["SECRET_KEY"] = "change-me"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "lab.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024  # 256 MB

db = SQLAlchemy(app)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

from flask import request, redirect, url_for
from flask_login import current_user

# Endpoints that should stay publicly accessible
LOGIN_EXEMPT = {
    "auth_login",        # GET/POST login page
    "auth_register",     # GET/POST signup page
    "static",       # bootstrap/css/js
    "view_sample_public",   # new public view
    "view_sample_public_short",  # <-- add this
    "sample_qr",            # QR image itself
}

@app.before_request
def require_login_for_all_pages():
    # When Flask can't resolve an endpoint (404), request.endpoint may be None
    ep = request.endpoint or ""
    if ep in LOGIN_EXEMPT:
        return  # allow through

    # If user is signed in, allow
    if current_user.is_authenticated:
        return

    # Otherwise, bounce to login with ?next=
    return redirect(url_for("auth_login", next=request.url))


# --- Models ---
# --- Visibility constants ---
VIS_INHERIT = "inherit"   # use database default
VIS_PRIVATE = "private"   # login + membership required
VIS_PUBLIC  = "public"    # no login required to view

# --- Database / Workspace ---
class Database(db.Model):
    __tablename__ = "database"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, unique=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    default_visibility = db.Column(db.String(16), default=VIS_PRIVATE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship("User")
    projects = db.relationship("Project", backref="database", cascade="all, delete-orphan")


class DatabaseMember(db.Model):
    __tablename__ = "database_member"
    id = db.Column(db.Integer, primary_key=True)
    database_id = db.Column(db.Integer, db.ForeignKey("database.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="viewer")  # owner, admin, editor, viewer
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    database = db.relationship("Database", backref=db.backref("members", cascade="all, delete-orphan"))
    user     = db.relationship("User")


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(120))
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    pi_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    pi = db.relationship("User", foreign_keys=[pi_user_id])

    experiments = db.relationship(
        "Experiment", backref="project", cascade="all, delete-orphan"
    )
    samples = db.relationship(
        "Sample", backref="project", cascade="all, delete-orphan"
    )
    database_id = db.Column(db.Integer, db.ForeignKey("database.id"))   # NEW
    visibility  = db.Column(db.String(16), default=VIS_INHERIT)         # NEW
    creator_id  = db.Column(db.Integer, db.ForeignKey("user.id"))       # NEW
    creator     = db.relationship("User", foreign_keys=[creator_id])     # NEW


class Experiment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # NEW: parent/children within the same table
    parent_id = db.Column(db.Integer, db.ForeignKey("experiment.id"))
    parent = db.relationship(
        "Experiment",
        remote_side=[id],
        backref=db.backref("children", cascade="all, delete-orphan")
    )

    documents = db.relationship("Document", backref="experiment", cascade="all, delete-orphan")
    # sample_links is via backref on SampleExperiment
    creator_id  = db.Column(db.Integer, db.ForeignKey("user.id"))       # NEW
    creator     = db.relationship("User", foreign_keys=[creator_id])     # NEW



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
    creator_id  = db.Column(db.Integer, db.ForeignKey("user.id"))       # NEW
    creator     = db.relationship("User", foreign_keys=[creator_id])     # NEW


class SampleDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey("sample.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(500), nullable=False)
    mimetype = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.post("/experiment/<int:experiment_id>/edit")
def edit_experiment_details(experiment_id):
    exp = Experiment.query.get_or_404(experiment_id)
    title = (request.form.get("title") or "").strip()
    details = (request.form.get("details") or "").strip()
    if not title:
        flash("Title is required.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))
    exp.title = title
    exp.description = details
    db.session.commit()
    flash("Experiment updated.", "ok")
    return redirect(url_for("view_experiment", experiment_id=exp.id))


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

# --- Project-defined Sample Attributes ---

# --- Project-defined Sample Attributes ---
class ProjectSampleAttribute(db.Model):
    __tablename__ = "project_sample_attribute"
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    field_type = db.Column(db.String(20), default="text")   # "text", "number", "select", "date"
    required = db.Column(db.Boolean, default=False)
    choices_json = db.Column(db.Text)                       # for select
    sort_order = db.Column(db.Integer, default=0)
    unit = db.Column(db.String(32))                         # <-- NEW (optional)

    project = db.relationship(
        "Project",
        backref=db.backref("sample_attributes", cascade="all, delete-orphan")
    )


class SampleAttributeValue(db.Model):
    __tablename__ = "sample_attribute_value"
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey("sample.id"), nullable=False)
    attribute_id = db.Column(db.Integer, db.ForeignKey("project_sample_attribute.id"), nullable=False)
    value = db.Column(db.Text)
    # NEW fields you added:
    is_placeholder = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sample = db.relationship("Sample", backref=db.backref("attribute_values", cascade="all, delete-orphan"))
    attribute = db.relationship("ProjectSampleAttribute")


# --- Helpers ---
def is_project_public(project):
    if project.visibility == VIS_PUBLIC:
        return True
    if project.visibility == VIS_INHERIT and project.database and project.database.default_visibility == VIS_PUBLIC:
        return True
    return False

def db_role(user, database_id):
    if not user or not getattr(user, "is_authenticated", False):
        return None
    m = DatabaseMember.query.filter_by(database_id=database_id, user_id=user.id).first()
    return m.role if m else None

def can_view_project(project, user):
    if is_project_public(project):
        return True
    return db_role(user, project.database_id) is not None

def can_edit_project(project, user):
    role = db_role(user, project.database_id)
    return role in ("owner", "admin", "editor") or (project.creator_id and user and getattr(user, "is_authenticated", False) and user.id == project.creator_id)

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

def build_experiment_lineage(exp):
    """Return list [root ... parent] for breadcrumb display."""
    chain = []
    cur = exp.parent
    while cur:
        chain.insert(0, cur)
        cur = cur.parent
    return chain

def get_experiment_descendant_ids(exp):
    """All descendant experiment IDs (to block cycles when reparenting)."""
    seen = set()
    stack = list(exp.children)
    while stack:
        node = stack.pop()
        if node.id in seen:
            continue
        seen.add(node.id)
        stack.extend(node.children)
    return seen

# --- Experiment tree helpers ---

def get_ancestors(exp):
    """Yield ancestors from parent up to root."""
    seen = set()
    cur = exp.parent
    while cur and cur.id not in seen:
        yield cur
        seen.add(cur.id)
        cur = cur.parent

def get_descendants(exp):
    """Yield all descendants (DFS)."""
    seen = set()
    stack = list(exp.children)
    while stack:
        n = stack.pop()
        if n.id in seen:
            continue
        seen.add(n.id)
        yield n
        stack.extend(n.children)

def would_create_cycle_as_parent(current, candidate_parent):
    """Invalid if parent == current or parent is a descendant of current."""
    if candidate_parent.id == current.id:
        return True
    return any(d.id == candidate_parent.id for d in get_descendants(current))

def would_create_cycle_as_child(current, candidate_child):
    """Invalid if child == current or child is an ancestor of current."""
    if candidate_child.id == current.id:
        return True
    return any(a.id == candidate_child.id for a in get_ancestors(current))

def build_linked_sample_tree(experiment):
    """
    Return a forest (list of roots) of linked samples organized by their
    parent/child relations, but restricted to samples linked to this experiment.
    Each node is: {"sample": Sample, "link": SampleExperiment, "children": [...]}
    """
    links = list(experiment.sample_links)  # SampleExperiment rows
    nodes = {}

    # make a node per linked sample
    for link in links:
        s = link.sample
        nodes[s.id] = {"sample": s, "link": link, "children": []}

    roots = []
    # wire up parent/child within the linked set only
    for node in nodes.values():
        s = node["sample"]
        if s.parent_id in nodes:
            nodes[s.parent_id]["children"].append(node)
        else:
            roots.append(node)

    # sort nicely
    def sort_tree(n):
        n["children"].sort(key=lambda x: (x["sample"].name or "").lower())
        for c in n["children"]:
            sort_tree(c)

    for r in roots:
        sort_tree(r)
    roots.sort(key=lambda n: (n["sample"].name or "").lower())
    return roots

def serialize_sample_tree(node, current_id=None, linked_ids=None):
    """Convert Sample tree to a dict usable by Jinja recursion."""
    children = sorted(node.children, key=lambda s: (s.name or "").lower())
    return {
        "id": node.id,
        "name": node.name,
        "is_current": (current_id is not None and node.id == current_id),
        "is_linked": (linked_ids is not None and node.id in linked_ids),
        "children": [serialize_sample_tree(c, current_id) for c in children],
    }


def get_project_attrs(project_id: int):
    return (ProjectSampleAttribute.query
            .filter_by(project_id=project_id)
            .order_by(ProjectSampleAttribute.sort_order.asc(), ProjectSampleAttribute.id.asc())
            .all())

def get_db_members_for_project(project):
    """Return list of Users who are members of the project's database."""
    # Adjust names if your membership model differs
    try:
        return (User.query
                .join(DatabaseMember, DatabaseMember.user_id == User.id)
                .filter(DatabaseMember.database_id == project.database_id)
                .order_by(User.name.asc())
                .all())
    except Exception:
        # Fallback: no membership model available – return empty list
        return []
    
def can_manage_project(project):
    """Allow DB owner/admin or project creator to set PI."""
    if not current_user.is_authenticated:
        return False
    # if you track creator on Project:
    if getattr(project, "creator_id", None) == current_user.id:
        return True
    try:
        memb = DatabaseMember.query.filter_by(
            database_id=project.database_id, user_id=current_user.id
        ).first()
        return bool(memb and memb.role in ("owner", "admin"))
    except Exception:
        # If no membership model yet, be permissive (or return False)
        return True
    
def get_full_experiment_chain(exp):
    """Return [root ... selected] for the given experiment."""
    chain = []
    cur = exp
    while cur:
        chain.insert(0, cur)
        cur = cur.parent  # requires Experiment.parent from your parent/child work
    return chain

def link_sample_to_experiment_with_lineage(sample, selected_exp, role="other", notes=""):
    """
    Create SampleExperiment links for the selected experiment AND all of its ancestors.
    - Selected experiment gets the chosen role.
    - Ancestors get role='ancestor' (so you can filter/display distinctly).
    - Avoids duplicate links.
    """
    chain = get_full_experiment_chain(selected_exp)
    for exp in chain:
        role_here = role if exp.id == selected_exp.id else "ancestor"
        exists = SampleExperiment.query.filter_by(
            sample_id=sample.id, experiment_id=exp.id, role=role_here
        ).first()
        if not exists:
            link_notes = notes if exp.id == selected_exp.id else (notes or f"via {selected_exp.title}")
            db.session.add(SampleExperiment(
                sample_id=sample.id,
                experiment_id=exp.id,
                role=role_here,
                notes=link_notes
            ))
    db.session.commit()

def get_sample_lineage(sample):
    """Return [root, ..., sample]."""
    chain = []
    cur = sample
    while cur:
        chain.insert(0, cur)
        cur = cur.parent
    return chain

def get_sample_root(sample):
    cur = sample
    while cur.parent is not None:
        cur = cur.parent
    return cur

def serialize_experiment_tree(node, current_id):
    kids = sorted(node.children, key=lambda e: (e.title or "").lower())
    return {
        "id": node.id,
        "title": node.title,
        "is_current": node.id == current_id,
        "children": [serialize_experiment_tree(c, current_id) for c in kids],
    }



# --- Routes ---
# ---- Login ----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        pw    = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(pw):
            login_user(user)
            flash("Welcome back!", "ok")
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        flash("Invalid email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "ok")
    return redirect(url_for("index"))

@app.route("/register", methods=["GET","POST"])
def register():
    # Optional: lock this down later; for now allows first users to sign up
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        name  = (request.form.get("name") or "").strip()
        pw    = request.form.get("password") or ""
        if not email or not pw:
            flash("Email and password required.", "error")
            return redirect(url_for("auth_register"))
        if User.query.filter_by(email=email).first():
            flash("Email already in use.", "error")
            return redirect(url_for("auth_register"))
        u = User(email=email, name=name)
        u.set_password(pw)
        db.session.add(u); db.session.commit()
        flash("Account created. You can now sign in.", "ok")
        return redirect(url_for("login"))
    return render_template("auth_register.html")


@app.route("/auth/login", methods=["GET", "POST"])
def auth_login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth_login"))

        login_user(user, remember=remember)
        next_url = request.args.get("next") or url_for("index")
        return redirect(next_url)

    return render_template("auth_login.html")


@app.route("/auth/register", methods=["GET", "POST"])
def auth_register():
    # Optional: set a config flag to disable open registration
    # if not app.config.get("ALLOW_REGISTRATION", True): abort(403)

    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm  = request.form.get("confirm") or ""

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("auth_register"))
        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("auth_register"))
        if User.query.filter_by(email=email).first():
            flash("That email is already registered.", "error")
            return redirect(url_for("auth_register"))

        u = User(name=name or email.split("@")[0], email=email)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        login_user(u)
        flash("Welcome!", "ok")
        return redirect(url_for("index"))

    return render_template("auth_register.html")


@app.post("/auth/logout")
@login_required
def auth_logout():
    logout_user()
    flash("Signed out.", "ok")
    return redirect(url_for("index"))

@app.route("/")
def index():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template("index.html", projects=projects)  # expects {{ projects }}

from flask import abort

@app.before_request
def require_login_for_all_pages():
    ep = request.endpoint or ""

    # Allow some endpoints without login
    if ep in LOGIN_EXEMPT:
        return

    # Allow document download if explicitly allowed
    if ep == "download_sample_doc" and app.config.get("PUBLIC_DOWNLOADS"):
        return

    if current_user.is_authenticated:
        return
    return redirect(url_for("login", next=request.url))


@app.post("/project/<int:project_id>/set-pi")
@login_required
def set_project_pi(project_id):
    project = Project.query.get_or_404(project_id)

    if not can_manage_project(project):
        abort(403)

    uid = request.form.get("pi_user_id", type=int)

    if uid:
        # must be a member of this project's database
        members = get_db_members_for_project(project)
        member_ids = {u.id for u in members}
        if uid not in member_ids:
            flash("Selected user is not a member of this database.", "error")
            return redirect(url_for("view_project", project_id=project.id))
        project.pi_user_id = uid
    else:
        # allow clearing PI
        project.pi_user_id = None

    db.session.commit()
    flash("PI updated.", "ok")
    return redirect(url_for("view_project", project_id=project.id))


# ---- Sample Attributes ----
@app.route("/project/<int:project_id>/sample-attrs/add", methods=["POST"])
def add_sample_attribute(project_id):
    p = Project.query.get_or_404(project_id)
    name = (request.form.get("name") or "").strip()
    field_type = (request.form.get("field_type") or "text").strip().lower()
    required = bool(request.form.get("required"))
    sort_order = request.form.get("sort_order", type=int)
    choices = (request.form.get("choices") or "").strip()
    unit = (request.form.get("unit") or "").strip()  # <-- NEW

    if not name:
        flash("Attribute name is required.", "error")
        return redirect(url_for("view_project", project_id=p.id))
    if field_type not in {"text", "number", "select", "date"}:
        flash("Invalid field type.", "error")
        return redirect(url_for("view_project", project_id=p.id))

    choices_json = None
    if field_type == "select":
        opts = [c.strip() for c in choices.split(",") if c.strip()]
        if not opts:
            flash("Select fields need at least one choice.", "error")
            return redirect(url_for("view_project", project_id=p.id))
        choices_json = json.dumps(opts)

    attr = ProjectSampleAttribute(
        project_id=p.id,
        name=name,
        field_type=field_type,
        required=required,
        choices_json=choices_json,
        sort_order=sort_order or 0,
        unit=(unit or None),  # <-- NEW
    )
    db.session.add(attr); db.session.commit()
       
    # Create placeholder values for all existing samples in this project
    existing_sample_ids = [sid for (sid,) in db.session.query(Sample.id).filter_by(project_id=project_id)]
    # which samples already have a value for this attr?
    has_val_ids = {sid for (sid,) in db.session.query(SampleAttributeValue.sample_id)
                   .filter_by(attribute_id=attr.id)}

    created = 0
    for sid in existing_sample_ids:
        if sid not in has_val_ids:
            db.session.add(SampleAttributeValue(
                sample_id=sid,
                attribute_id=attr.id,
                value="PLEASE UPDATE",
                is_placeholder=True
            ))
            created += 1
    db.session.commit()

    flash(f"Sample attribute added. {created} sample(s) marked as needing update.", "ok")
    return redirect(url_for("view_project", project_id=p.id))


@app.route("/project/sample-attrs/<int:attr_id>/delete", methods=["POST"])
def delete_sample_attribute(attr_id):
    attr = ProjectSampleAttribute.query.get_or_404(attr_id)
    pid = attr.project_id

    # Delete all values for this attribute
    deleted = SampleAttributeValue.query.filter_by(attribute_id=attr.id).delete(synchronize_session=False)
    db.session.delete(attr)
    db.session.commit()

    flash(f"Attribute removed. {deleted} value(s) deleted from samples.", "ok")
    return redirect(url_for("view_project", project_id=pid))


@app.route("/api/project/<int:project_id>/sample-attrs")
def api_project_sample_attrs(project_id):
    attrs = get_project_attrs(project_id)
    def serialize(a: ProjectSampleAttribute):
        return {
            "id": a.id,
            "name": a.name,
            "field_type": a.field_type,
            "required": bool(a.required),
            "choices": (json.loads(a.choices_json) if a.choices_json else []),
            "unit": a.unit or ""
        }
    return jsonify([serialize(a) for a in attrs])

# ---- Projects ----
@app.route("/projects/create", methods=["POST"])
def create_project():
    title = request.form.get("title", "").strip()
    desc = request.form.get("description", "").strip()
    if not title:
        flash("Project title is required.", "error")
        return redirect(url_for("index"))
    project = Project(title=title, description=desc, creator_id=_uid())
    db.session.add(project)
    db.session.commit()
    return redirect(url_for("view_project", project_id=project.id))


@app.route("/project/<int:project_id>")
def view_project(project_id):
    project = Project.query.get_or_404(project_id)

    roots = (Sample.query
             .filter_by(project_id=project.id, parent_id=None)
             .order_by(Sample.name.asc())
             .all())
    sample_tree = [serialize_sample_tree(r) for r in roots]

    pi_candidates = get_db_members_for_project(project)
    can_manage = can_manage_project(project)

    return render_template(
        "project.html",
        project=project,
        sample_tree=sample_tree,
        pi_candidates=pi_candidates,
        can_manage=can_manage,
    )




@app.route("/project/<int:project_id>/experiments/create", methods=["POST"])
def create_experiment(project_id):
    project = Project.query.get_or_404(project_id)
    title = request.form.get("title", "").strip()
    desc = request.form.get("description", "").strip()
    if not title:
        flash("Experiment title is required.", "error")
        return redirect(url_for("view_project", project_id=project_id))
    experiment = Experiment(project=project, title=title, description=desc, creator_id=_uid())
    db.session.add(experiment)
    db.session.commit()
    return redirect(url_for("view_experiment", experiment_id=experiment.id))


# ---- Experiments ----
@app.get("/experiment/<int:experiment_id>")
def view_experiment(experiment_id):
    exp = Experiment.query.get_or_404(experiment_id)

    # Build exp_tree from root ancestor to show in template
    root = exp
    while root.parent:
        root = root.parent
    exp_tree = serialize_experiment_tree(root, exp.id)

    # Choices (exclude anything that would cause cycles)
    all_exps = Experiment.query.filter_by(project_id=exp.project_id).all()
    # Parent candidates: not self or descendants
    parent_choices = [
        e for e in all_exps
        if e.id != exp.id and not would_create_cycle_as_parent(exp, e)
    ]
    # Child candidates: not self or ancestors
    child_choices = [
        e for e in all_exps
        if e.id != exp.id and not would_create_cycle_as_child(exp, e)
    ]
     # Linked samples: build sample tree but highlight linked ones
    linked_ids = {link.sample_id for link in exp.sample_links}
    sample_roots = [s for s in exp.project.samples if not s.parent_id]
    linked_sample_tree = [serialize_sample_tree(r) for r in sample_roots]

    return render_template(
        "experiment.html",
        experiment=exp,
        exp_tree=exp_tree,
        parent_choices=parent_choices,
        child_choices=child_choices,
        linked_sample_tree=linked_sample_tree[0] if linked_sample_tree else None,
        linked_sample_ids=linked_ids,
    )


@app.route("/experiment/<int:experiment_id>/split", methods=["POST"])
def split_experiment(experiment_id):
    parent = Experiment.query.get_or_404(experiment_id)
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()

    if not title:
        flash("Child experiment title is required.", "error")
        return redirect(url_for("view_experiment", experiment_id=parent.id))

    child = Experiment(
        project_id=parent.project_id,
        parent_id=parent.id,
        title=title,
        description=description
    )
    db.session.add(child)
    db.session.commit()
    flash("Child experiment created.", "ok")
    return redirect(url_for("view_experiment", experiment_id=child.id))

@app.route("/experiment/<int:experiment_id>/reparent", methods=["POST"])
def reparent_experiment(experiment_id):
    exp = Experiment.query.get_or_404(experiment_id)
    new_parent_id = request.form.get("parent_id", type=int)

    # Clear parent (make root)
    if not new_parent_id:
        exp.parent_id = None
        db.session.commit()
        flash("Parent cleared (experiment is now a root).", "ok")
        return redirect(url_for("view_experiment", experiment_id=exp.id))

    parent = Experiment.query.get_or_404(new_parent_id)

    # Guardrails
    if parent.id == exp.id:
        flash("An experiment cannot be its own parent.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))
    if parent.project_id != exp.project_id:
        flash("Parent must be in the same project.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))

    # Prevent cycles: walk up the ancestry
    cur = parent
    while cur:
        if cur.id == exp.id:
            flash("Invalid parent: would create a cycle.", "error")
            return redirect(url_for("view_experiment", experiment_id=exp.id))
        cur = cur.parent

    exp.parent_id = parent.id
    db.session.commit()
    flash("Parent updated.", "ok")
    return redirect(url_for("view_experiment", experiment_id=exp.id))

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
    parent_id  = request.form.get("parent_id", type=int)
    project_id = request.form.get("project_id", type=int)
    name       = (request.form.get("name") or "").strip()

    # NEW: optional experiment link on creation
    experiment_id = request.form.get("experiment_id", type=int)
    link_role     = (request.form.get("role") or "other").strip().lower()
    link_notes    = (request.form.get("notes") or "").strip()

    parent = Sample.query.get(parent_id) if parent_id else None
    if parent:
        project_id = parent.project_id

    if not project_id or not name:
        flash("Project (or parent) and sample name are required.", "error")
        return redirect(url_for("list_samples"))

    # validate dynamic attributes (your existing logic here) ...
    attrs = get_project_attrs(project_id)
    values_to_save = []
    missing = []
    for a in attrs:
        key = f"attr_{a.id}"
        val = (request.form.get(key) or "").strip()
        if a.required and not val:
            missing.append(a.name)
        values_to_save.append((a.id, val))
    if missing:
        flash("Missing required attributes: " + ", ".join(missing), "error")
        return redirect(url_for("list_samples", view=request.args.get("view","project")))

    # create the sample
    sample = Sample(project_id=project_id, parent_id=(parent.id if parent else None), name=name, creator_id=_uid())
    db.session.add(sample); db.session.commit()

    # persist attribute values
    for attr_id, val in values_to_save:
        db.session.add(SampleAttributeValue(sample_id=sample.id, attribute_id=attr_id, value=val))
    db.session.commit()

    # NEW: link to experiment + all ancestors (enforce same-project)
    if experiment_id:
        exp = Experiment.query.get_or_404(experiment_id)
        if exp.project_id != project_id:
            flash("Selected experiment must belong to the same project as the sample.", "error")
        else:
            link_sample_to_experiment_with_lineage(sample, exp, role=link_role, notes=link_notes)

    flash("Sample created.", "ok")
    return redirect(url_for("view_sample", sample_id=sample.id))

@app.get("/public/sample/<int:sample_id>")
def view_sample_public(sample_id):
    sample = Sample.query.get_or_404(sample_id)

    # lineage & tree
    lineage = get_sample_lineage(sample)
    family_tree = serialize_sample_tree(get_sample_root(sample), sample.id)

    # attributes (read-only)
    attrs = get_project_attrs(sample.project_id)
    val_by_attr = {v.attribute_id: v for v in sample.attribute_values}
    attr_defs = []
    for a in attrs:
        v = val_by_attr.get(a.id)
        attr_defs.append({
            "id": a.id,
            "name": a.name,
            "unit": getattr(a, "unit", None),  # safe if unit column exists
            "value": (v.value if v and v.value else None),
        })

    # whether to allow file downloads to unauthenticated users
    public_downloads = bool(app.config.get("PUBLIC_DOWNLOADS", False))

    return render_template(
        "sample_public.html",
        sample=sample,
        lineage=lineage,
        family_tree=family_tree,
        attr_defs=attr_defs,
        public_downloads=public_downloads,
    )


@app.get("/s/<int:sample_id>")
def view_sample_public_short(sample_id):
    return view_sample_public(sample_id)


@app.route("/sample/<int:sample_id>/qr")
def sample_qr(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    url = url_for("view_sample_public", sample_id=sample.id, _external=True)
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/sample/<int:sample_id>/split", methods=["POST"])
def split_sample(sample_id):
    parent = Sample.query.get_or_404(sample_id)
    child_name = (request.form.get("name") or "").strip()

    if not child_name:
        flash("Child name is required.", "error")
        return redirect(url_for("view_sample", sample_id=parent.id))

    # Required attributes for the parent's project
    attrs = get_project_attrs(parent.project_id)

    missing = []
    values = {}

    for a in attrs:
        key = f"attr_{a.id}"
        val = (request.form.get(key) or "").strip()
        if a.required and not val:
            missing.append(a.name)
        values[a.id] = val

    if missing:
        flash("Missing required attributes: " + ", ".join(missing), "error")
        return redirect(url_for("view_sample", sample_id=parent.id))

    # Create the child
    child = Sample(
        project_id=parent.project_id,
        parent_id=parent.id,
        name=child_name,
        creator_id=_uid(),
    )
    db.session.add(child); db.session.commit()

    # Persist attribute values on the child
    for attr_id, val in values.items():
        db.session.add(SampleAttributeValue(sample_id=child.id, attribute_id=attr_id, value=val))
    db.session.commit()

    flash("Child sample created.", "ok")
    return redirect(url_for("view_sample", sample_id=child.id))


@app.route("/sample/<int:sample_id>")
def view_sample(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    exp_choices = Experiment.query.filter_by(project_id=sample.project_id).order_by(Experiment.created_at.desc()).all()

    # lineage & tree (if you already added them) ...
    lineage = get_sample_lineage(sample)

    # Build defs for display + editing
    attrs = get_project_attrs(sample.project_id)
    val_by_attr = {v.attribute_id: v for v in sample.attribute_values}

    needs_update = 0
    attr_defs = []
    for a in attrs:
        v = val_by_attr.get(a.id)
        value = v.value if v else ""
        placeholder = (v.is_placeholder if v else True) if value == "PLEASE UPDATE" or (not v) else bool(v.is_placeholder)
        if (not v) or placeholder:
            needs_update += 1
        attr_defs.append({
            "id": a.id,
            "name": a.name,
            "field_type": a.field_type,
            "required": bool(a.required),
            "choices": (json.loads(a.choices_json) if a.choices_json else []),
            "value": value,
            "is_placeholder": placeholder,
            "unit": a.unit or ""
        })

    return render_template(
        "sample.html",
        sample=sample,
        exp_choices=exp_choices,
        lineage=lineage,
        family_tree = serialize_sample_tree(get_sample_root(sample), sample.id),
        attr_defs=attr_defs,
        needs_update=needs_update,
    )

@app.context_processor
def inject_global_counts():
    return dict(global_counts={
        "projects": Project.query.count(),
        "samples": Sample.query.count(),
        "experiments": Experiment.query.count(),
    })


@app.route("/sample/<int:sample_id>/link", methods=["POST"])
def link_experiment(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    experiment_id = request.form.get("experiment_id", type=int)
    notes = (request.form.get("notes") or "").strip()

    if not experiment_id:
        flash("Please choose an experiment.", "error")
        return redirect(url_for("view_sample", sample_id=sample.id))

    selected = Experiment.query.get_or_404(experiment_id)
    if selected.project_id != sample.project_id:
        flash("Selected experiment must belong to the same project as the sample.", "error")
        return redirect(url_for("view_sample", sample_id=sample.id))

    # Link selected + its ancestors (helper prevents duplicates)
    link_sample_to_experiment_with_lineage(sample, selected, role="other", notes=notes)
    flash("Experiment linked (including lineage).", "ok")
    return redirect(url_for("view_sample", sample_id=sample.id))


@app.post("/experiment/<int:experiment_id>/link/parent")
def link_existing_parent(experiment_id):
    current = Experiment.query.get_or_404(experiment_id)
    parent_id = request.form.get("parent_id", type=int)
    if not parent_id:
        flash("Select a parent experiment.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))

    parent = Experiment.query.get_or_404(parent_id)

    # Same project?
    if parent.project_id != current.project_id:
        flash("Parent must be in the same project.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))

    # Cycle protection
    if would_create_cycle_as_parent(current, parent):
        flash("That link would create a cycle.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))

    current.parent = parent  # reparent if it already had a parent
    db.session.commit()
    flash("Parent linked.", "ok")
    return redirect(url_for("view_experiment", experiment_id=current.id))

@app.post("/experiment/<int:experiment_id>/link/child")
def link_existing_child(experiment_id):
    current = Experiment.query.get_or_404(experiment_id)
    child_id = request.form.get("child_id", type=int)
    if not child_id:
        flash("Select a child experiment.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))

    child = Experiment.query.get_or_404(child_id)

    # Same project?
    if child.project_id != current.project_id:
        flash("Child must be in the same project.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))

    # Cycle protection
    if would_create_cycle_as_child(current, child):
        flash("That link would create a cycle.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))

    child.parent = current  # reparent if it already had a parent
    db.session.commit()
    flash("Child linked.", "ok")
    return redirect(url_for("view_experiment", experiment_id=current.id))


@app.route("/sample/link/<int:link_id>/delete", methods=["POST"])
def unlink_experiment(link_id):
    link = SampleExperiment.query.get_or_404(link_id)
    sid = link.sample_id
    db.session.delete(link)
    db.session.commit()
    flash("Link removed.", "ok")
    return redirect(url_for("view_sample", sample_id=sid))

@app.post("/experiment/<int:experiment_id>/unlink/parent")
def unlink_parent_experiment(experiment_id):
    current = Experiment.query.get_or_404(experiment_id)
    if not current.parent_id:
        flash("No parent to unlink.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))
    current.parent = None
    db.session.commit()
    flash("Parent unlinked.", "ok")
    return redirect(url_for("view_experiment", experiment_id=current.id))


@app.post("/experiment/<int:experiment_id>/unlink/child/<int:child_id>")
def unlink_child_experiment(experiment_id, child_id):
    current = Experiment.query.get_or_404(experiment_id)
    child = Experiment.query.get_or_404(child_id)
    if child.parent_id != current.id:
        flash("That experiment is not a direct child of this one.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))
    child.parent = None
    db.session.commit()
    flash("Child unlinked.", "ok")
    return redirect(url_for("view_experiment", experiment_id=current.id))


@app.post("/experiment/<int:experiment_id>/create/parent")
def create_parent_experiment(experiment_id):
    current = Experiment.query.get_or_404(experiment_id)
    title = (request.form.get("title") or "").strip()
    details = (request.form.get("details") or "").strip()
    if not title:
        flash("Title is required for the new parent.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))

    parent = Experiment(
        project_id=current.project_id,
        title=title,
        description=details,
        creator_id=_uid()
    )
    db.session.add(parent)
    db.session.flush()  # get parent.id without full commit

    # No cycle possible here (parent is new), just link
    current.parent = parent
    db.session.commit()
    flash("Parent experiment created and linked.", "ok")
    return redirect(url_for("view_experiment", experiment_id=current.id))

@app.post("/experiment/<int:experiment_id>/create/child")
def create_child_experiment(experiment_id):
    current = Experiment.query.get_or_404(experiment_id)
    title = (request.form.get("title") or "").strip()
    details = (request.form.get("details") or "").strip()
    if not title:
        flash("Title is required for the new child.", "error")
        return redirect(url_for("view_experiment", experiment_id=current.id))

    child = Experiment(
        project_id=current.project_id,
        title=title,
        description=details,
        parent=current,
        creator_id=_uid()
    )
    db.session.add(child)
    db.session.commit()
    flash("Child experiment created and linked.", "ok")
    return redirect(url_for("view_experiment", experiment_id=current.id))


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

@app.route("/sample/<int:sample_id>/edit", methods=["POST"])
def edit_sample(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    new_name = (request.form.get("name") or "").strip()
    if new_name:
        sample.name = new_name

    attrs = get_project_attrs(sample.project_id)
    existing = {v.attribute_id: v for v in sample.attribute_values}

    missing_required = []
    for a in attrs:
        key = f"attr_{a.id}"
        val = (request.form.get(key) or "").strip()

        if a.required and not val:
            missing_required.append(a.name)
            continue

        row = existing.get(a.id)
        if row:
            row.value = val
            row.is_placeholder = False
        else:
            db.session.add(SampleAttributeValue(
                sample_id=sample.id,
                attribute_id=a.id,
                value=val,
                is_placeholder=False
            ))
    if missing_required:
        flash("Missing required attributes: " + ", ".join(missing_required), "error")
        return redirect(url_for("view_sample", sample_id=sample.id))

    db.session.commit()
    flash("Sample updated.", "ok")
    return redirect(url_for("view_sample", sample_id=sample.id))


# --- Bootstrap DB on first run ---



with app.app_context():
    db.create_all()

    from sqlalchemy.exc import OperationalError

    def add_column_if_missing(table: str, column: str, ddl: str):
        with db.engine.begin() as conn:
            cols = [row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()]
            if column in cols:
                return
            try:
                conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {ddl}")
            except OperationalError as e:
                if "duplicate column name" in str(e).lower():
                    pass
                else:
                    raise

    # Project
    add_column_if_missing("project", "pi_user_id",    "pi_user_id INTEGER")
    add_column_if_missing("project", "database_id",   "database_id INTEGER")
    add_column_if_missing("project", "visibility",    "visibility TEXT")
    add_column_if_missing("project", "creator_id",    "creator_id INTEGER")

    # Experiment
    add_column_if_missing("experiment", "parent_id",  "parent_id INTEGER")
    add_column_if_missing("experiment", "creator_id", "creator_id INTEGER")

    # Sample
    add_column_if_missing("sample", "parent_id",      "parent_id INTEGER")
    add_column_if_missing("sample", "creator_id",     "creator_id INTEGER")

    # Attributes / values
    add_column_if_missing("project_sample_attribute", "unit", "unit TEXT")
    add_column_if_missing("sample_attribute_value",   "is_placeholder", "is_placeholder BOOLEAN")
    add_column_if_missing("sample_attribute_value",   "updated_at",     "updated_at DATETIME")


    

if __name__ == "__main__":
    app.run(debug=True)
