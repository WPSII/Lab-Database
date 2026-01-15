import os
import io
import json
import re
from datetime import datetime, timedelta

from flask import (
    Flask, abort, request, redirect, url_for, render_template,
    send_from_directory, send_file, flash, jsonify, session
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
import sqlite3
from helpers import (
    safe_json_loads,
    get_sample_lineage, get_sample_root,
    get_full_experiment_chain, get_experiment_descendant_ids,
    get_ancestors, get_descendants,
    would_create_cycle_as_parent, would_create_cycle_as_child,
    serialize_sample_tree, serialize_experiment_tree,
    build_linked_sample_tree,
)


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
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + \
    os.path.join(BASE_DIR, "lab.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024  # 256 MB

db = SQLAlchemy(app)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def add_column_if_missing(table: str, column: str, coltype: str):
    """Idempotently add a column to an SQLite table if it doesn't exist.

    Uses PRAGMA table_info(table) to detect existing columns. Safe to call
    at app startup. Silent on failure but logs exceptions.
    """
    try:
        # PRAGMA returns rows like (cid,name,type,notnull,dflt_value,pk)
        res = db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()
        existing = [r[1] for r in res]
        if column in existing:
            return False
        # ALTER TABLE ADD COLUMN is supported by SQLite for simple additions
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))
        db.session.commit()
        app.logger.info(f"Added column {column} to {table}")
        return True
    except Exception as e:
        # don't break startup; log and continue
        try:
            app.logger.exception(f"Failed to ensure column {column} on {table}: {e}")
        except Exception:
            pass
        db.session.rollback()
        return False


# Track whether we've attempted runtime migrations in this process
RUNTIME_MIGRATED = False


def ensure_runtime_columns_once():
    """Attempt to add missing nullable columns once per process.

    This is safe to call from a request context; it will no-op after the
    first attempt.
    """
    global RUNTIME_MIGRATED
    if RUNTIME_MIGRATED:
        return
    try:
        if app.config.get('SQLALCHEMY_DATABASE_URI', '').startswith('sqlite:'):
            # Prefer a direct sqlite3 connection to perform PRAGMA/ALTER
            # — this avoids SQLAlchemy scoped-session issues in some runtimes.
            uri = app.config.get('SQLALCHEMY_DATABASE_URI')
            # expect form sqlite:///absolute/path
            db_path = None
            if uri.startswith('sqlite:///'):
                db_path = uri.replace('sqlite:///', '')
            elif uri.startswith('sqlite://'):
                db_path = uri.replace('sqlite://', '')

            def _add_if_missing_sqlite(path, table, column, coltype):
                try:
                    conn = sqlite3.connect(path)
                    cur = conn.cursor()
                    cur.execute(f"PRAGMA table_info({table})")
                    cols = [r[1] for r in cur.fetchall()]
                    if column in cols:
                        conn.close()
                        return False
                    cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
                    conn.commit()
                    conn.close()
                    try:
                        app.logger.info(f"Added column {column} to {table} via sqlite3")
                    except Exception:
                        pass
                    return True
                except Exception:
                    try:
                        app.logger.exception(f"Failed to add {column} to {table} via sqlite3")
                    except Exception:
                        pass
                    try:
                        conn and conn.close()
                    except Exception:
                        pass
                    return False

            if db_path:
                _add_if_missing_sqlite(db_path, 'project', 'start_date', 'DATE')
                _add_if_missing_sqlite(db_path, 'project', 'end_date', 'DATE')
                _add_if_missing_sqlite(db_path, 'equipment', 'project_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'stock_material', 'sample_class_id', 'INTEGER')
            else:
                # fallback to SQLAlchemy helper
                add_column_if_missing('project', 'start_date', 'DATE')
                add_column_if_missing('project', 'end_date', 'DATE')
                add_column_if_missing('equipment', 'project_id', 'INTEGER')
                add_column_if_missing('stock_material', 'sample_class_id', 'INTEGER')
    except Exception:
        try:
            app.logger.exception('Failed to ensure runtime columns')
        except Exception:
            pass
    finally:
        RUNTIME_MIGRATED = True

# Note: we avoid using @app.before_first_request due to environment differences.
# Instead, call ensure_runtime_columns_once() from request handlers (before_request)


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
    # ensure DB schema additions are present (runs once)
    try:
        ensure_runtime_columns_once()
    except Exception:
        pass
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
VIS_PUBLIC = "public"    # no login required to view

# --- Database / Workspace ---


class Database(db.Model):
    __tablename__ = "database"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, unique=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    default_visibility = db.Column(db.String(16), default=VIS_PRIVATE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship("User")
    projects = db.relationship(
        "Project", backref="database", cascade="all, delete-orphan")


class DatabaseMember(db.Model):
    __tablename__ = "database_member"
    id = db.Column(db.Integer, primary_key=True)
    database_id = db.Column(db.Integer, db.ForeignKey(
        "database.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # owner, admin, editor, viewer
    role = db.Column(db.String(16), nullable=False, default="viewer")
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    database = db.relationship("Database", backref=db.backref(
        "members", cascade="all, delete-orphan"))
    user = db.relationship("User")


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
    # optional start/end dates for project lifecycle
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)

    pi_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    pi = db.relationship("User", foreign_keys=[pi_user_id])

    experiments = db.relationship(
        "Experiment", backref="project", cascade="all, delete-orphan"
    )
    samples = db.relationship(
        "Sample", backref="project", cascade="all, delete-orphan"
    )
    database_id = db.Column(db.Integer, db.ForeignKey("database.id"))   # NEW
    visibility = db.Column(db.String(16), default=VIS_INHERIT)         # NEW
    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))       # NEW
    creator = db.relationship("User", foreign_keys=[creator_id])     # NEW


class Experiment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey(
        "project.id"), nullable=False)
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
    # optional timeline fields
    start_at = db.Column(db.DateTime, nullable=True)
    end_at = db.Column(db.DateTime, nullable=True)

    documents = db.relationship(
        "Document", backref="experiment", cascade="all, delete-orphan")
    # sample_links is via backref on SampleExperiment
    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))       # NEW
    creator = db.relationship("User", foreign_keys=[creator_id])     # NEW


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    experiment_id = db.Column(db.Integer, db.ForeignKey(
        "experiment.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)     # original name
    # absolute path on disk
    stored_path = db.Column(db.String(500), nullable=False)
    mimetype = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


# --- Sample models ---
class Sample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey(
        "project.id"), nullable=False)
    # NEW:
    parent_id = db.Column(db.Integer, db.ForeignKey(
        "sample.id"))  # nullable root
    parent = db.relationship("Sample",
                             remote_side=[id],
                             backref=db.backref("children", cascade="all, delete-orphan"))

    name = db.Column(db.String(160), nullable=False)
    manufacturer = db.Column(db.String(160))
    composition = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    documents = db.relationship(
        "SampleDocument", backref="sample", cascade="all, delete-orphan")
    experiment_links = db.relationship(
        "SampleExperiment", backref="sample", cascade="all, delete-orphan")
    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))       # NEW
    creator = db.relationship("User", foreign_keys=[creator_id])     # NEW


class SampleDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey(
        "sample.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(500), nullable=False)
    mimetype = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


@app.post("/experiment/<int:experiment_id>/edit")
def edit_experiment_details(experiment_id):
    exp = Experiment.query.get_or_404(experiment_id)
    title = (request.form.get("title") or "").strip()
    details = (request.form.get("details") or "").strip()
    # optional start/end datetimes from the edit form
    start_raw = (request.form.get("start_at") or "").strip()
    end_raw = (request.form.get("end_at") or "").strip()
    if not title:
        flash("Title is required.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))
    exp.title = title
    exp.description = details
    # Parse datetimes if provided (expecting HTML datetime-local format: YYYY-MM-DDTHH:MM)
    try:
        if start_raw:
            exp.start_at = datetime.fromisoformat(start_raw)
        else:
            exp.start_at = None
    except Exception:
        flash("Invalid start datetime format.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))

    try:
        if end_raw:
            exp.end_at = datetime.fromisoformat(end_raw)
        else:
            exp.end_at = None
    except Exception:
        flash("Invalid end datetime format.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))
    db.session.commit()
    flash("Experiment updated.", "ok")
    return redirect(url_for("view_experiment", experiment_id=exp.id))


class SampleExperiment(db.Model):
    """Many-to-many link: a Sample can be acted on by many Experiments (with a role)."""
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey(
        "sample.id"), nullable=False)
    experiment_id = db.Column(db.Integer, db.ForeignKey(
        "experiment.id"), nullable=False)
    # irradiation, corrosion, polishing, other
    role = db.Column(db.String(40), nullable=False, default="other")
    notes = db.Column(db.Text)

    experiment = db.relationship(
        "Experiment", backref=db.backref("sample_links", cascade="all, delete-orphan")
    )

# --- Project-defined Sample Attributes ---

# --- Project-defined Sample Attributes ---


class ProjectSampleAttribute(db.Model):
    __tablename__ = "project_sample_attribute"
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey(
        "project.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    # "text", "number", "select", "date"
    field_type = db.Column(db.String(20), default="text")
    required = db.Column(db.Boolean, default=False)
    choices_json = db.Column(db.Text)                       # for select
    sort_order = db.Column(db.Integer, default=0)
    # <-- NEW (optional)
    unit = db.Column(db.String(32))
    # Whether this attribute should be inherited by child samples and locked there
    inherited = db.Column(db.Boolean, default=False)

    project = db.relationship(
        "Project",
        backref=db.backref("sample_attributes", cascade="all, delete-orphan")
    )


class SampleAttributeValue(db.Model):
    __tablename__ = "sample_attribute_value"
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey(
        "sample.id"), nullable=False)
    attribute_id = db.Column(db.Integer, db.ForeignKey(
        "project_sample_attribute.id"), nullable=False)
    value = db.Column(db.Text)
    # NEW fields you added:
    is_placeholder = db.Column(db.Boolean, default=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sample = db.relationship("Sample", backref=db.backref(
        "attribute_values", cascade="all, delete-orphan"))
    attribute = db.relationship("ProjectSampleAttribute")


# ---- New models for Sample Classes and Equipment tracking ----


class SampleClass(db.Model):
    __tablename__ = "sample_class"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, unique=True)
    slug = db.Column(db.String(160), nullable=True, unique=True)
    description = db.Column(db.Text)
    attributes_json = db.Column(db.Text)  # JSON string describing class attributes/defaults
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ProjectSampleClass(db.Model):
    __tablename__ = "project_sample_class"
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    sample_class_id = db.Column(db.Integer, db.ForeignKey("sample_class.id"), nullable=False)
    name_override = db.Column(db.String(160))
    attributes_override_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    project = db.relationship("Project")
    sample_class = db.relationship("SampleClass")


# Add class links to existing Sample model (nullable for backward compat)
# NOTE: Sample class is defined earlier in this file; we add columns dynamically
try:
    if not hasattr(Sample, 'sample_class_id'):
        Sample.sample_class_id = db.Column(db.Integer, db.ForeignKey('sample_class.id'), nullable=True)
        Sample.project_class_id = db.Column(db.Integer, db.ForeignKey('project_sample_class.id'), nullable=True)
        Sample.class_attrs_json = db.Column(db.Text)
        Sample.stock_material_id = db.Column(db.Integer, db.ForeignKey('stock_material.id'), nullable=True)
        Sample.sample_class = db.relationship('SampleClass', foreign_keys=[Sample.sample_class_id])
        Sample.project_class = db.relationship('ProjectSampleClass', foreign_keys=[Sample.project_class_id])
        Sample.stock_material = db.relationship('StockMaterial', foreign_keys=[Sample.stock_material_id])
except NameError:
    # If Sample isn't in globals yet (unexpected), ignore; models will be wired when file loads normally
    pass


class Equipment(db.Model):
    __tablename__ = 'equipment'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    model = db.Column(db.String(200))
    serial_number = db.Column(db.String(200), unique=True)
    location = db.Column(db.String(200))
    manufacturer = db.Column(db.String(200))
    purchase_date = db.Column(db.Date)
    max_weight = db.Column(db.Float)  # optional
    temperature_compensation_json = db.Column(db.Text)  # JSON string for coefficients
    status = db.Column(db.String(32), default='active')  # active/retired
    calibration_interval_days = db.Column(db.Integer)  # default schedule in days
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # optional project scoping for equipment (nullable)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)
    project = db.relationship('Project', foreign_keys=[project_id])

    def last_calibration(self):
        return CalibrationLog.query.filter_by(equipment_id=self.id).order_by(CalibrationLog.performed_at.desc()).first()

    def next_due_date(self):
        last = self.last_calibration()
        if not last or not self.calibration_interval_days:
            return None
        return last.performed_at + timedelta(days=self.calibration_interval_days)

    def calibration_status(self, warn_days=7):
        """Return 'no_schedule', 'ok', 'due_soon', or 'overdue'"""
        nd = self.next_due_date()
        if nd is None:
            return 'no_schedule'
        now = datetime.utcnow()
        if nd < now:
            return 'overdue'
        if nd - now <= timedelta(days=warn_days):
            return 'due_soon'
        return 'ok'


class MaintenanceLog(db.Model):
    __tablename__ = 'maintenance_log'
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    performed_by = db.Column(db.String(200))
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)
    maintenance_type = db.Column(db.String(100))
    notes = db.Column(db.Text)
    next_due_date = db.Column(db.DateTime)

    equipment = db.relationship('Equipment', backref=db.backref('maintenance_logs', cascade='all, delete-orphan'))


class CalibrationLog(db.Model):
    __tablename__ = 'calibration_log'
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    performed_by = db.Column(db.String(200))
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)
    values_json = db.Column(db.Text)   # JSON list of {"ref": <value>, "measured": <value>} or simple pairs
    temperature = db.Column(db.Float)
    summary_json = db.Column(db.Text)  # computed summary (bias, slope, r2, etc.) as JSON string
    next_due_date = db.Column(db.DateTime)

    equipment = db.relationship('Equipment', backref=db.backref('calibration_logs', cascade='all, delete-orphan'))


class SampleMeasurement(db.Model):
    __tablename__ = 'sample_measurement'
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey('sample.id'), nullable=False)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiment.id'))
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'))
    measured_at = db.Column(db.DateTime, default=datetime.utcnow)
    operator = db.Column(db.String(200))
    values_json = db.Column(db.Text)  # JSON payload for measurement channels
    temperature = db.Column(db.Float)
    metadata_json = db.Column(db.Text)

    sample = db.relationship('Sample', backref=db.backref('measurements', cascade='all, delete-orphan'))
    experiment = db.relationship('Experiment')
    equipment = db.relationship('Equipment')


class ExperimentEquipment(db.Model):
    __tablename__ = 'experiment_equipment'
    id = db.Column(db.Integer, primary_key=True)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiment.id'), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    role = db.Column(db.String(80))
    notes = db.Column(db.Text)

    experiment = db.relationship('Experiment', backref=db.backref('equipment_links', cascade='all, delete-orphan'))
    equipment = db.relationship('Equipment')


class StockMaterial(db.Model):
    __tablename__ = 'stock_material'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    lot_number = db.Column(db.String(120))
    quantity = db.Column(db.Float)
    unit = db.Column(db.String(64))
    location = db.Column(db.String(200))
    manufacturer = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # optional link to a SampleClass (categorize stock materials)
    sample_class_id = db.Column(db.Integer, db.ForeignKey('sample_class.id'), nullable=True)
    sample_class = db.relationship('SampleClass', foreign_keys=[sample_class_id])

    def __repr__(self):
        return f"<StockMaterial {self.id} {self.name}>"


class SOP(db.Model):
    __tablename__ = 'sop'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text)
    version = db.Column(db.String(32))
    effective_date = db.Column(db.Date)
    created_by = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ExperimentLog(db.Model):
    __tablename__ = 'experiment_log'
    id = db.Column(db.Integer, primary_key=True)
    experiment_id = db.Column(db.Integer, db.ForeignKey('experiment.id'), nullable=False)
    user = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    attachments_json = db.Column(db.Text)

    experiment = db.relationship('Experiment', backref=db.backref('logs', cascade='all, delete-orphan'))



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
    m = DatabaseMember.query.filter_by(
        database_id=database_id, user_id=user.id).first()
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


def safe_json_loads(text, default=None):
    """Safely load JSON from text, returning default on error or when text is falsy.

    Use default=[] for expecting arrays.
    """
    if not text:
        return default if default is not None else []
    try:
        return json.loads(text)
    except Exception:
        return default if default is not None else []


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
            link_notes = notes if exp.id == selected_exp.id else (
                notes or f"via {selected_exp.title}")
            db.session.add(SampleExperiment(
                sample_id=sample.id,
                experiment_id=exp.id,
                role=role_here,
                notes=link_notes
            ))
    db.session.commit()


# --- Routes ---
# ---- Login ----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
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
        confirm = request.form.get("confirm") or ""

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
    try:
        projects = Project.query.order_by(Project.created_at.desc()).all()
    except OperationalError as e:
        app.logger.warning('OperationalError querying Projects index, attempting runtime migration: %s', e)
        try:
            ensure_runtime_columns_once()
        except Exception:
            pass
        # retry once
        projects = Project.query.order_by(Project.created_at.desc()).all()
    # expects {{ projects }}
    return render_template("index.html", projects=projects)


@app.route('/projects/all')
def all_projects():
    try:
        today = datetime.utcnow().date()
        # Current projects: have a start_date and no end_date set
        current = Project.query.filter(Project.start_date != None, Project.end_date == None).order_by(Project.start_date.asc()).all()
        # Archive: end_date set and before today
        archive = Project.query.filter(Project.end_date != None, Project.end_date < today).order_by(Project.end_date.desc()).all()
    except OperationalError as e:
        app.logger.warning('OperationalError querying Projects list, attempting runtime migration: %s', e)
        try:
            add_column_if_missing('project', 'start_date', 'DATE')
            add_column_if_missing('project', 'end_date', 'DATE')
        except Exception:
            pass
        # retry
        today = datetime.utcnow().date()
        current = Project.query.filter(Project.start_date != None, Project.end_date == None).order_by(Project.start_date.asc()).all()
        archive = Project.query.filter(Project.end_date != None, Project.end_date < today).order_by(Project.end_date.desc()).all()

    return render_template('all_projects.html', current=current, archive=archive)


@app.before_request
def require_login_for_all_pages():
    # ensure runtime columns present (attempt once)
    try:
        ensure_runtime_columns_once()
    except Exception:
        pass
    ep = request.endpoint or ""

    # Allow some endpoints without login
    if ep in LOGIN_EXEMPT:
        return

    # Allow document download if explicitly allowed
    if ep == "download_sample_doc" and app.config.get("PUBLIC_DOWNLOADS"):
        return

    if current_user.is_authenticated:
        return
    # Redirect to canonical login view (auth_login) to support login_manager configuration
    return redirect(url_for("auth_login", next=request.url))


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


@app.post('/project/<int:project_id>/edit-dates')
@login_required
def edit_project_dates(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(project):
        abort(403)

    start_raw = (request.form.get('start_date') or '').strip()
    end_raw = (request.form.get('end_date') or '').strip()

    try:
        if start_raw:
            project.start_date = datetime.fromisoformat(start_raw).date()
        else:
            project.start_date = None
    except Exception:
        flash('Invalid project start date format.', 'error')
        return redirect(url_for('view_project', project_id=project.id))

    try:
        if end_raw:
            project.end_date = datetime.fromisoformat(end_raw).date()
        else:
            project.end_date = None
    except Exception:
        flash('Invalid project end date format.', 'error')
        return redirect(url_for('view_project', project_id=project.id))

    db.session.commit()
    flash('Project dates updated.', 'ok')
    return redirect(url_for('view_project', project_id=project.id))


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
    db.session.add(attr)
    db.session.commit()

    # Create placeholder values for all existing samples in this project
    existing_sample_ids = [sid for (sid,) in db.session.query(
        Sample.id).filter_by(project_id=project_id)]
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
    deleted = SampleAttributeValue.query.filter_by(
        attribute_id=attr.id).delete(synchronize_session=False)
    db.session.delete(attr)
    db.session.commit()

    flash(f"Attribute removed. {deleted} value(s) deleted from samples.", "ok")
    return redirect(url_for("view_project", project_id=pid))


@app.route("/project/<int:project_id>/sample-classes/add", methods=["POST"])
def add_project_sample_class(project_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(project):
        abort(403)
    psc_id = request.form.get('psc_id', type=int)
    sample_class_id = request.form.get('sample_class_id', type=int)
    name_override = (request.form.get('name_override') or '').strip() or None
    attrs_raw = (request.form.get('attributes') or '').strip()

    if not sample_class_id:
        flash('Select a Sample Class to add to this project.', 'error')
        return redirect(url_for('view_project', project_id=project.id))

    try:
        attrs = json.loads(attrs_raw) if attrs_raw else None
        if attrs is not None and not isinstance(attrs, list):
            raise ValueError('attributes must be a JSON array')
    except Exception as e:
        flash('Invalid attributes JSON: ' + str(e), 'error')
        return redirect(url_for('view_project', project_id=project.id))

    if psc_id:
        psc = ProjectSampleClass.query.get_or_404(psc_id)
        if psc.project_id != project.id:
            abort(403)
        psc.sample_class_id = sample_class_id
        psc.name_override = name_override
        psc.attributes_override_json = json.dumps(attrs) if attrs is not None else None
    else:
        psc = ProjectSampleClass(project_id=project.id, sample_class_id=sample_class_id,
                                 name_override=name_override, attributes_override_json=json.dumps(attrs) if attrs is not None else None)
        db.session.add(psc)

    db.session.commit()
    flash('Project sample class saved.', 'ok')
    return redirect(url_for('view_project', project_id=project.id))


@app.route('/project/<int:project_id>/sample-classes/<int:psc_id>/delete', methods=['POST'])
def delete_project_sample_class(project_id, psc_id):
    project = Project.query.get_or_404(project_id)
    if not can_manage_project(project):
        abort(403)
    psc = ProjectSampleClass.query.get_or_404(psc_id)
    if psc.project_id != project.id:
        abort(403)
    db.session.delete(psc)
    db.session.commit()
    flash('Project sample class removed.', 'ok')
    return redirect(url_for('view_project', project_id=project.id))


@app.route('/api/project/<int:project_id>/sample-class/<int:class_id>/attrs')
def api_project_class_attrs(project_id, class_id):
    # Return merged attributes: lab-level class attrs overridden/extended by project-specific attrs
    sc = SampleClass.query.get_or_404(class_id)
    base_attrs = safe_json_loads(sc.attributes_json, [])

    psc = ProjectSampleClass.query.filter_by(project_id=project_id, sample_class_id=class_id).first()
    if psc and psc.attributes_override_json:
        override = safe_json_loads(psc.attributes_override_json, [])
        # simple merge: attributes with same name replaced by override; new ones appended
        merged = []
        names = {a.get('name'): a for a in override}
        for a in base_attrs:
            if a.get('name') in names:
                merged.append(names.pop(a.get('name')))
            else:
                merged.append(a)
        # append any remaining overrides
        merged.extend(names.values())
    else:
        merged = base_attrs

    return jsonify(merged)


@app.route("/api/project/<int:project_id>/sample-attrs")
def api_project_sample_attrs(project_id):
    attrs = get_project_attrs(project_id)

    def serialize(a: ProjectSampleAttribute):
        return {
            "id": a.id,
            "name": a.name,
            "field_type": a.field_type,
            "required": bool(a.required),
            "choices": safe_json_loads(a.choices_json, []),
            "unit": a.unit or "",
            "inherited": bool(getattr(a, 'inherited', False))
        }
    return jsonify([serialize(a) for a in attrs])


@app.route('/api/sample/<int:sample_id>/attr-values')
def api_sample_attr_values(sample_id):
    s = Sample.query.get_or_404(sample_id)
    root = get_sample_root(s)
    vals = SampleAttributeValue.query.filter_by(sample_id=root.id).all()
    out = {str(v.attribute_id): v.value for v in vals}
    return jsonify(out)

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
    try:
        project = Project.query.get_or_404(project_id)
    except OperationalError as e:
        # likely missing columns on older SQLite DBs; attempt to add them then retry once
        app.logger.warning('OperationalError querying Project, attempting runtime migration: %s', e)
        try:
            add_column_if_missing('project', 'start_date', 'DATE')
            add_column_if_missing('project', 'end_date', 'DATE')
        except Exception:
            pass
        # retry
        project = Project.query.get_or_404(project_id)

    roots = (Sample.query
             .filter_by(project_id=project.id, parent_id=None)
             .order_by(Sample.name.asc())
             .all())
    sample_tree = [serialize_sample_tree(r) for r in roots]

    pi_candidates = get_db_members_for_project(project)
    can_manage = can_manage_project(project)

    # sample class options (lab-level) and project-specific sample classes
    sample_classes = SampleClass.query.order_by(SampleClass.name.asc()).all()
    project_sample_classes = ProjectSampleClass.query.filter_by(project_id=project.id).all()

    return render_template(
        "project.html",
        project=project,
        sample_tree=sample_tree,
        pi_candidates=pi_candidates,
        can_manage=can_manage,
        sample_classes=sample_classes,
        project_sample_classes=project_sample_classes,
    )


@app.route('/project/<int:project_id>/timeline')
def project_timeline(project_id):
    """Return timeline events for the project grouped by year-month.
    Events returned include experiments (start/end/created), sample creations,
    maintenance and calibration entries for equipment used in project experiments,
    measurements, documents and experiment logs.
    """
    project = Project.query.get_or_404(project_id)
    events = []

    # experiments
    exps = project.experiments or []
    for e in exps:
        # only include explicit start/end times on the timeline (omit creation time)
        if getattr(e, 'start_at', None):
            events.append({
                'type': 'experiment_start',
                'timestamp': e.start_at.isoformat(),
                'title': e.title,
                'id': e.id,
                'url': url_for('view_experiment', experiment_id=e.id)
            })
        if getattr(e, 'end_at', None):
            events.append({
                'type': 'experiment_end',
                'timestamp': e.end_at.isoformat(),
                'title': e.title,
                'id': e.id,
                'url': url_for('view_experiment', experiment_id=e.id)
            })

    # samples (creation)
    for s in project.samples:
        if s.created_at:
            events.append({
                'type': 'sample_created',
                'timestamp': s.created_at.isoformat(),
                'title': s.name,
                'id': s.id,
                'url': url_for('view_sample', sample_id=s.id)
            })

    # equipment used in this project's experiments
    exp_ids = [e.id for e in exps]
    eq_ids = set()
    if exp_ids:
        for e in exps:
            for link in getattr(e, 'equipment_links', []):
                eq_ids.add(link.equipment_id)

    if eq_ids:
        m_logs = MaintenanceLog.query.filter(MaintenanceLog.equipment_id.in_(list(eq_ids))).all()
        for m in m_logs:
            if m.performed_at:
                events.append({
                    'type': 'maintenance',
                    'timestamp': m.performed_at.isoformat(),
                    'title': f"Maintenance ({m.maintenance_type or 'maintenance'})",
                    'id': m.id,
                    'equipment_id': m.equipment_id,
                    'performed_by': m.performed_by,
                    'url': url_for('view_equipment', equipment_id=m.equipment_id) if 'view_equipment' in globals() else None
                })

        cal_logs = CalibrationLog.query.filter(CalibrationLog.equipment_id.in_(list(eq_ids))).all()
        for c in cal_logs:
            if c.performed_at:
                events.append({
                    'type': 'calibration',
                    'timestamp': c.performed_at.isoformat(),
                    'title': 'Calibration',
                    'id': c.id,
                    'equipment_id': c.equipment_id,
                    'performed_by': c.performed_by,
                    'url': url_for('view_equipment', equipment_id=c.equipment_id) if 'view_equipment' in globals() else None
                })

    # measurements attached to experiments
    if exp_ids:
        measurements = SampleMeasurement.query.filter(SampleMeasurement.experiment_id.in_(exp_ids)).all()
        for m in measurements:
            if m.measured_at:
                events.append({
                    'type': 'measurement',
                    'timestamp': m.measured_at.isoformat(),
                    'title': f"Measurement (sample {m.sample_id})",
                    'id': m.id,
                    'sample_id': m.sample_id,
                    'experiment_id': m.experiment_id,
                    'equipment_id': m.equipment_id,
                    'url': url_for('view_sample', sample_id=m.sample_id) if 'view_sample' in globals() else None
                })

    # experiment logs & documents
    for e in exps:
        for l in getattr(e, 'logs', []):
            if l.timestamp:
                events.append({
                    'type': 'experiment_log',
                    'timestamp': l.timestamp.isoformat(),
                    'title': 'Log entry',
                    'id': l.id,
                    'notes': l.notes,
                    'url': url_for('view_experiment', experiment_id=e.id)
                })
        for d in getattr(e, 'documents', []):
            if d.uploaded_at:
                events.append({
                    'type': 'document',
                    'timestamp': d.uploaded_at.isoformat(),
                    'title': d.filename,
                    'id': d.id,
                    'url': url_for('view_experiment', experiment_id=e.id)
                })

    # server-side filtering by event types (optional)
    types_param = (request.args.get('types') or '').strip()
    if types_param:
        allowed = set([t.strip() for t in types_param.split(',') if t.strip()])
        events = [ev for ev in events if ev.get('type') in allowed]

    # Group by year-month
    grouped = {}
    for ev in events:
        try:
            ts = ev.get('timestamp')
            # ts is ISO string; extract YYYY-MM
            key = ts[:7]
        except Exception:
            key = 'unknown'
        grouped.setdefault(key, []).append(ev)

    # sort events in each month descending
    for k in grouped:
        grouped[k].sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    # return a simple JSON mapping month->list
    return jsonify(grouped)


@app.route("/project/<int:project_id>/experiments/create", methods=["POST"])
def create_experiment(project_id):
    project = Project.query.get_or_404(project_id)
    title = request.form.get("title", "").strip()
    desc = request.form.get("description", "").strip()
    if not title:
        flash("Experiment title is required.", "error")
        return redirect(url_for("view_project", project_id=project_id))
    experiment = Experiment(project=project, title=title,
                            description=desc, creator_id=_uid())
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

    # equipment choices scoped to project (nullable project_id means global)
    try:
        equipment_choices = Equipment.query.filter(
            (Equipment.project_id == exp.project_id) | (Equipment.project_id == None)
        ).order_by(Equipment.name).all()
    except Exception:
        # If Equipment has no project_id column yet (older DB), fall back to all equipment
        equipment_choices = Equipment.query.order_by(Equipment.name).all()

    return render_template(
        "experiment.html",
        experiment=exp,
        exp_tree=exp_tree,
        parent_choices=parent_choices,
        child_choices=child_choices,
        linked_sample_tree=linked_sample_tree[0] if linked_sample_tree else None,
        linked_sample_ids=linked_ids,
        equipment_choices=equipment_choices,
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


@app.route("/experiment/<int:experiment_id>/equipment/add", methods=["POST"])
def add_experiment_equipment(experiment_id):
    exp = Experiment.query.get_or_404(experiment_id)
    equipment_id = request.form.get("equipment_id", type=int)
    role = (request.form.get("role") or "").strip()
    notes = (request.form.get("notes") or "").strip()
    if not equipment_id:
        flash("Equipment selection required.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))
    eq = Equipment.query.get_or_404(equipment_id)
    link = ExperimentEquipment(experiment_id=exp.id, equipment_id=eq.id, role=role, notes=notes)
    db.session.add(link)
    db.session.commit()
    flash("Equipment linked.", "ok")
    return redirect(url_for("view_experiment", experiment_id=exp.id))


@app.route("/experiment/<int:experiment_id>/child-sample/create", methods=["POST"])
def experiment_create_child_sample(experiment_id):
    exp = Experiment.query.get_or_404(experiment_id)
    parent_sample_id = request.form.get("parent_sample_id", type=int)
    child_name = (request.form.get("name") or "").strip()
    if not parent_sample_id or not child_name:
        flash("Parent sample and child name required.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))
    parent = Sample.query.get_or_404(parent_sample_id)
    if parent.project_id != exp.project_id:
        flash("Selected sample does not belong to this project.", "error")
        return redirect(url_for("view_experiment", experiment_id=exp.id))

    child = Sample(
        project_id=exp.project_id,
        parent_id=parent.id,
        name=child_name,
        creator_id=_uid(),
        stock_material_id = getattr(get_sample_root(parent), 'stock_material_id', None),
    )
    # copy class attrs if present
    child.class_attrs_json = getattr(parent, 'class_attrs_json', None)
    db.session.add(child)
    db.session.commit()

    # copy attribute values from parent to child
    try:
        vals = SampleAttributeValue.query.filter_by(sample_id=parent.id).all()
        for v in vals:
            nv = SampleAttributeValue(
                sample_id=child.id,
                attribute_id=v.attribute_id,
                value=v.value,
                is_placeholder=getattr(v, 'is_placeholder', False)
            )
            db.session.add(nv)
        db.session.commit()
    except Exception:
        db.session.rollback()

    # link the new child to this experiment
    db.session.add(SampleExperiment(sample_id=child.id, experiment_id=exp.id))
    db.session.commit()
    flash("Child sample created and linked to experiment.", "ok")
    return redirect(url_for("view_experiment", experiment_id=exp.id))


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
    directory, name = os.path.dirname(
        d.stored_path), os.path.basename(d.stored_path)
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
    roots_by_project = {
        p.id: [s for s in p.samples if not s.parent_id] for p in projects}

    # options for dependent dropdowns
    experiment_opts = [
        {"id": e.id, "title": e.title, "project_id": e.project_id}
        for e in Experiment.query.order_by(Experiment.created_at.desc()).all()
    ]
    sample_opts = [
        {"id": s.id, "name": s.name, "project_id": s.project_id, "stock_material_id": (s.stock_material_id if hasattr(s, 'stock_material_id') else None)}
        for s in Sample.query.order_by(Sample.created_at.desc()).all()
    ]
    stock_material_opts = [
        {"id": m.id, "name": m.name, "lot_number": m.lot_number}
        for m in StockMaterial.query.order_by(StockMaterial.name.asc()).all()
    ]
    sample_class_opts = []
    for sc in SampleClass.query.order_by(SampleClass.name.asc()).all():
        attrs = safe_json_loads(sc.attributes_json, [])
        sample_class_opts.append({
            "id": sc.id,
            "name": sc.name,
            "description": sc.description,
            "attributes": attrs,
        })

    return render_template(
        "samples.html",
        samples=samples,
        projects=projects,
        roots_by_project=roots_by_project,
        experiment_opts=experiment_opts,
        sample_opts=sample_opts,
        sample_class_opts=sample_class_opts,
        q=q,
        view=view,
        stock_material_opts=stock_material_opts,
    )


@app.route('/api/sample-classes')
def api_sample_classes():
    out = []
    for sc in SampleClass.query.order_by(SampleClass.name.asc()).all():
        try:
            attrs = safe_json_loads(sc.attributes_json, [])
        except Exception:
            attrs = []
        out.append({
            'id': sc.id,
            'name': sc.name,
            'description': sc.description,
            'attributes': attrs,
        })
    return jsonify(out)


@app.route('/stock-materials')
def list_stock_materials():
    sample_classes = SampleClass.query.order_by(SampleClass.name.asc()).all()
    materials = StockMaterial.query.order_by(StockMaterial.name.asc()).all()
    materials_by_class = {sc.id: [] for sc in sample_classes}
    uncategorized = []
    for m in materials:
        if m.sample_class_id:
            materials_by_class.setdefault(m.sample_class_id, []).append(m)
        else:
            uncategorized.append(m)
    return render_template('stock_inventory.html', sample_classes=sample_classes, materials_by_class=materials_by_class, uncategorized=uncategorized)


@app.route('/stock-materials/create', methods=['POST'])
def create_stock_material():
    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Name required for stock material.', 'error')
        return redirect(url_for('list_stock_materials'))
    m = StockMaterial(
        name=name,
        lot_number=(request.form.get('lot_number') or '').strip(),
        quantity=request.form.get('quantity', type=float),
        unit=(request.form.get('unit') or '').strip(),
        location=(request.form.get('location') or '').strip(),
        manufacturer=(request.form.get('manufacturer') or '').strip(),
        description=(request.form.get('description') or '').strip(),
        sample_class_id=request.form.get('sample_class_id', type=int)
    )
    db.session.add(m)
    db.session.commit()
    flash('Stock material created.', 'ok')
    return redirect(url_for('list_stock_materials'))


@app.route('/equipment')
def list_equipment():
    # Show all equipment; project filtering available in experiment pages
    eqs = Equipment.query.order_by(Equipment.name.asc()).all()
    return render_template('equipment.html', equipment=eqs)


@app.route('/sample-classes/create', methods=['POST'])
def create_sample_class():
    name = (request.form.get('name') or '').strip()
    description = (request.form.get('description') or '').strip()
    slug = (request.form.get('slug') or '').strip()
    attrs_raw = (request.form.get('attributes') or '').strip()
    if not name:
        flash('Sample class name is required.', 'error')
        return redirect(url_for('list_samples'))

    if not slug:
        slug = re.sub('[^0-9a-z]+', '_', name.lower())

    # attrs_raw is expected to be JSON array of attribute objects
    try:
        attrs = json.loads(attrs_raw) if attrs_raw else []
        if not isinstance(attrs, list):
            raise ValueError('attributes must be a JSON array')
    except Exception as e:
        flash('Invalid attributes JSON: ' + str(e), 'error')
        return redirect(url_for('list_samples'))

    sc = SampleClass(name=name, slug=slug, description=description, attributes_json=json.dumps(attrs))
    db.session.add(sc)
    db.session.commit()
    flash('Sample class created.', 'ok')
    return redirect(url_for('list_samples'))


@app.route("/samples/create", methods=["POST"])
def create_sample():
    parent_id = request.form.get("parent_id", type=int)
    project_id = request.form.get("project_id", type=int)
    name = (request.form.get("name") or "").strip()

    # NEW: optional experiment link on creation
    experiment_id = request.form.get("experiment_id", type=int)
    link_role = (request.form.get("role") or "other").strip().lower()
    link_notes = (request.form.get("notes") or "").strip()

    parent = Sample.query.get(parent_id) if parent_id else None
    if parent:
        project_id = parent.project_id

    if not project_id or not name:
        flash("Project (or parent) and sample name are required.", "error")
        return redirect(url_for("list_samples"))

    # Handle sample class attributes (lab-level classes)
    sample_class_id = request.form.get('sample_class_id', type=int)
    class_attrs = []
    class_values = {}
    if sample_class_id:
        sc = SampleClass.query.get(sample_class_id)
        if sc:
            class_attrs = safe_json_loads(sc.attributes_json, [])
            # validate and collect values
            for a in class_attrs:
                aname = a.get('name')
                # slugify attribute name for form field
                slug = re.sub('[^0-9a-z]+', '_', (aname or '').lower())
                key = f'sc_{slug}'
                val = (request.form.get(key) or '').strip()
                if a.get('required') and not val:
                    flash(f"Missing required class attribute: {aname}", 'error')
                    return redirect(url_for('list_samples', view=request.args.get('view', 'project')))
                class_values[aname] = val

    # validate dynamic attributes (your existing logic here) ...
    attrs = get_project_attrs(project_id)
    values_to_save = []
    missing = []
    for a in attrs:
        key = f"attr_{a.id}"
        # If attribute is marked inherited, pull value from root parent (if any)
        if getattr(a, 'inherited', False):
            if parent:
                root = get_sample_root(parent)
                pav = SampleAttributeValue.query.filter_by(sample_id=root.id, attribute_id=a.id).first()
                val = (pav.value if pav else "")
                if a.required and not val:
                    missing.append(a.name)
                values_to_save.append((a.id, val))
            else:
                # no parent to inherit from
                val = ''
                if a.required:
                    missing.append(a.name)
                values_to_save.append((a.id, val))
        else:
            val = (request.form.get(key) or "").strip()
            if a.required and not val:
                missing.append(a.name)
            values_to_save.append((a.id, val))
    if missing:
        flash("Missing required attributes: " + ", ".join(missing), "error")
        return redirect(url_for("list_samples", view=request.args.get("view", "project")))

    # create the sample
    sample = Sample(project_id=project_id, parent_id=(
        parent.id if parent else None), name=name, creator_id=_uid())
    # handle stock material: only allow setting on root samples
    stock_material_id = request.form.get('stock_material_id', type=int)
    if parent:
        # inherit from root parent
        root = get_sample_root(parent)
        sample.stock_material_id = getattr(root, 'stock_material_id', None)
    else:
        sample.stock_material_id = stock_material_id if stock_material_id else None

    db.session.add(sample)
    db.session.commit()

    # persist attribute values
    for attr_id, val in values_to_save:
        db.session.add(SampleAttributeValue(
            sample_id=sample.id, attribute_id=attr_id, value=val))
    db.session.commit()

    # persist sample-class values if provided
    if class_values:
        try:
            sample.sample_class_id = sample_class_id
            sample.class_attrs_json = json.dumps(class_values)
            db.session.add(sample)
            db.session.commit()
        except Exception:
            # non-fatal: log and continue
            pass

        # If this is a root sample and it has a stock_material assigned, cascade to descendants (none yet),
        # but keep helper for future edits where changing root cascades.

    # NEW: link to experiment + all ancestors (enforce same-project)
    if experiment_id:
        exp = Experiment.query.get_or_404(experiment_id)
        if exp.project_id != project_id:
            flash(
                "Selected experiment must belong to the same project as the sample.", "error")
        else:
            link_sample_to_experiment_with_lineage(
                sample, exp, role=link_role, notes=link_notes)

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
        stock_material_id = getattr(get_sample_root(parent), 'stock_material_id', None),
    )
    db.session.add(child)
    db.session.commit()

    # Persist attribute values on the child
    for attr_id, val in values.items():
        db.session.add(SampleAttributeValue(
            sample_id=child.id, attribute_id=attr_id, value=val))
    db.session.commit()

    flash("Child sample created.", "ok")
    return redirect(url_for("view_sample", sample_id=child.id))


@app.route("/sample/<int:sample_id>")
def view_sample(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    exp_choices = Experiment.query.filter_by(
        project_id=sample.project_id).order_by(Experiment.created_at.desc()).all()

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
        placeholder = (v.is_placeholder if v else True) if value == "PLEASE UPDATE" or (
            not v) else bool(v.is_placeholder)
        if (not v) or placeholder:
            needs_update += 1
        attr_defs.append({
            "id": a.id,
            "name": a.name,
            "field_type": a.field_type,
            "required": bool(a.required),
            "choices": safe_json_loads(a.choices_json, []),
            "value": value,
            "is_placeholder": placeholder,
            "unit": a.unit or ""
        })

    return render_template(
        "sample.html",
        sample=sample,
        exp_choices=exp_choices,
        lineage=lineage,
        family_tree=serialize_sample_tree(get_sample_root(sample), sample.id),
        attr_defs=attr_defs,
        needs_update=needs_update,
        stock_materials=StockMaterial.query.order_by(StockMaterial.name.asc()).all(),
    )


@app.route('/stock/<int:stock_id>')
def view_stock_material(stock_id):
    mat = StockMaterial.query.get_or_404(stock_id)
    return render_template('stock_material.html', mat=mat)


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
    link_sample_to_experiment_with_lineage(
        sample, selected, role="other", notes=notes)
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

    # Only allow changing stock material on root samples
    if not sample.parent_id:
        new_sm = request.form.get('stock_material_id', type=int)
        old_sm = getattr(sample, 'stock_material_id', None)
        if new_sm and new_sm != old_sm:
            sample.stock_material_id = new_sm
            # cascade to descendants
            def cascade_sm(s, smid):
                for c in s.children:
                    c.stock_material_id = smid
                    cascade_sm(c, smid)
            cascade_sm(sample, new_sm)
        elif new_sm is None or new_sm == 0:
            # clearing stock material
            if old_sm:
                sample.stock_material_id = None
                def cascade_clear(s):
                    for c in s.children:
                        c.stock_material_id = None
                        cascade_clear(c)
                cascade_clear(sample)

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
        flash("Missing required attributes: " +
              ", ".join(missing_required), "error")
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
            cols = [row[1] for row in conn.exec_driver_sql(
                f"PRAGMA table_info({table})").fetchall()]
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
    # Sample: ensure newly-added class-related columns exist for older DBs
    add_column_if_missing("sample", "sample_class_id", "sample_class_id INTEGER")
    add_column_if_missing("sample", "project_class_id", "project_class_id INTEGER")
    add_column_if_missing("sample", "class_attrs_json", "class_attrs_json TEXT")
    add_column_if_missing("project", "visibility",    "visibility TEXT")
    add_column_if_missing("project", "creator_id",    "creator_id INTEGER")

    # Experiment
    add_column_if_missing("experiment", "parent_id",  "parent_id INTEGER")
    add_column_if_missing("experiment", "creator_id", "creator_id INTEGER")
    add_column_if_missing("experiment", "start_at", "start_at DATETIME")
    add_column_if_missing("experiment", "end_at", "end_at DATETIME")

    # Sample
    add_column_if_missing("sample", "parent_id",      "parent_id INTEGER")
    add_column_if_missing("sample", "creator_id",     "creator_id INTEGER")
    add_column_if_missing("sample", "stock_material_id", "stock_material_id INTEGER")
    # Equipment project scoping
    add_column_if_missing("equipment", "project_id", "project_id INTEGER")
    # Stock material sample class linking
    add_column_if_missing("stock_material", "sample_class_id", "sample_class_id INTEGER")

    # Attributes / values
    add_column_if_missing("project_sample_attribute", "unit", "unit TEXT")
    add_column_if_missing("project_sample_attribute", "inherited", "inherited BOOLEAN")
    add_column_if_missing("sample_attribute_value",
                          "is_placeholder", "is_placeholder BOOLEAN")
    add_column_if_missing("sample_attribute_value",
                          "updated_at",     "updated_at DATETIME")


if __name__ == "__main__":
    app.run(debug=True)
