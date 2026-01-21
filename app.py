import os
import io
import json
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import qrcode
import pycountry

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
from sqlalchemy import text, create_engine
from sqlalchemy.exc import OperationalError, IntegrityError
import sqlite3
from helpers import (
    safe_json_loads,
    safe_slug,
    save_uploaded_file,
    send_stored_file,
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
LABS_DIR = os.path.join(BASE_DIR, 'Labs')
os.makedirs(LABS_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "csv", "png", "jpg", "jpeg"}

app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = "auth_login"  # where to send non-authed users


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


app.config["SECRET_KEY"] = "change-me"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + \
    os.path.join(BASE_DIR, "backend.db")
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
                _add_if_missing_sqlite(db_path, 'project', 'slug', 'VARCHAR(160)')
                _add_if_missing_sqlite(db_path, 'project', 'start_date', 'DATE')
                _add_if_missing_sqlite(db_path, 'project', 'end_date', 'DATE')
                _add_if_missing_sqlite(db_path, 'equipment', 'project_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'equipment', 'database_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'equipment', 'facility_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'stock_material', 'sample_class_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'stock_material', 'database_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'stock_material', 'class_attrs_json', 'TEXT')
                _add_if_missing_sqlite(db_path, 'stock_material', 'original_quantity', 'FLOAT')
                _add_if_missing_sqlite(db_path, 'sample_class', 'database_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'document', 'uploaded_by_user_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'sample_document', 'uploaded_by_user_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'stock_material_document', 'uploaded_by_user_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'database', 'slug', 'VARCHAR(160)')
                _add_if_missing_sqlite(db_path, 'database', 'db_filename', 'VARCHAR(300)')
                _add_if_missing_sqlite(db_path, 'database', 'time_zone', 'VARCHAR(64)')
                _add_if_missing_sqlite(db_path, 'database', 'role_badge_owner', 'VARCHAR(32)')
                _add_if_missing_sqlite(db_path, 'database', 'role_badge_admin', 'VARCHAR(32)')
                _add_if_missing_sqlite(db_path, 'database', 'role_badge_editor', 'VARCHAR(32)')
                _add_if_missing_sqlite(db_path, 'database', 'role_badge_viewer', 'VARCHAR(32)')
                _add_if_missing_sqlite(db_path, 'facility', 'manager_user_id', 'INTEGER')
                _add_if_missing_sqlite(db_path, 'facility', 'slug', 'VARCHAR(160)')
                _add_if_missing_sqlite(db_path, 'facility', 'address_line1', 'VARCHAR(200)')
                _add_if_missing_sqlite(db_path, 'facility', 'address_line2', 'VARCHAR(200)')
                _add_if_missing_sqlite(db_path, 'facility', 'city', 'VARCHAR(120)')
                _add_if_missing_sqlite(db_path, 'facility', 'state', 'VARCHAR(120)')
                _add_if_missing_sqlite(db_path, 'facility', 'postal_code', 'VARCHAR(40)')
                _add_if_missing_sqlite(db_path, 'facility', 'country', 'VARCHAR(120)')
                _add_if_missing_sqlite(db_path, 'user', 'title', 'VARCHAR(120)')
                _add_if_missing_sqlite(db_path, 'user', 'phone', 'VARCHAR(64)')
                _add_if_missing_sqlite(db_path, 'user', 'organization', 'VARCHAR(160)')
                _add_if_missing_sqlite(db_path, 'user', 'bio', 'TEXT')
                # Ensure new tables exist (in particular the invitation table)
                try:
                    # create any missing tables for models declared in SQLAlchemy
                    db.create_all()
                except Exception:
                    try:
                        app.logger.exception('Failed to create missing tables via create_all')
                    except Exception:
                        pass
            try:
                db.session.execute(text("UPDATE database SET role_badge_owner = 'bg-hot-pink' WHERE role_badge_owner IS NULL OR role_badge_owner = 'bg-danger'"))
                db.session.commit()
            except Exception:
                db.session.rollback()
            else:
                # fallback to SQLAlchemy helper
                add_column_if_missing('project', 'slug', 'VARCHAR(160)')
                add_column_if_missing('project', 'start_date', 'DATE')
                add_column_if_missing('project', 'end_date', 'DATE')
                add_column_if_missing('equipment', 'project_id', 'INTEGER')
                add_column_if_missing('equipment', 'database_id', 'INTEGER')
                add_column_if_missing('equipment', 'facility_id', 'INTEGER')
                add_column_if_missing('stock_material', 'sample_class_id', 'INTEGER')
                add_column_if_missing('stock_material', 'database_id', 'INTEGER')
                add_column_if_missing('stock_material', 'class_attrs_json', 'TEXT')
                add_column_if_missing('stock_material', 'original_quantity', 'FLOAT')
                add_column_if_missing('sample_class', 'database_id', 'INTEGER')
                add_column_if_missing('document', 'uploaded_by_user_id', 'INTEGER')
                add_column_if_missing('sample_document', 'uploaded_by_user_id', 'INTEGER')
                add_column_if_missing('stock_material_document', 'uploaded_by_user_id', 'INTEGER')
                add_column_if_missing('database', 'slug', 'VARCHAR(160)')
                add_column_if_missing('database', 'db_filename', 'VARCHAR(300)')
                add_column_if_missing('database', 'time_zone', 'VARCHAR(64)')
                add_column_if_missing('database', 'role_badge_owner', 'VARCHAR(32)')
                add_column_if_missing('database', 'role_badge_admin', 'VARCHAR(32)')
                add_column_if_missing('database', 'role_badge_editor', 'VARCHAR(32)')
                add_column_if_missing('database', 'role_badge_viewer', 'VARCHAR(32)')
                add_column_if_missing('facility', 'manager_user_id', 'INTEGER')
                add_column_if_missing('facility', 'slug', 'VARCHAR(160)')
                add_column_if_missing('facility', 'address_line1', 'VARCHAR(200)')
                add_column_if_missing('facility', 'address_line2', 'VARCHAR(200)')
                add_column_if_missing('facility', 'city', 'VARCHAR(120)')
                add_column_if_missing('facility', 'state', 'VARCHAR(120)')
                add_column_if_missing('facility', 'postal_code', 'VARCHAR(40)')
                add_column_if_missing('facility', 'country', 'VARCHAR(120)')
                add_column_if_missing('user', 'title', 'VARCHAR(120)')
                add_column_if_missing('user', 'phone', 'VARCHAR(64)')
                add_column_if_missing('user', 'organization', 'VARCHAR(160)')
                add_column_if_missing('user', 'bio', 'TEXT')
                try:
                    db.create_all()
                except Exception:
                    try:
                        app.logger.exception('Failed to create missing tables via create_all')
                    except Exception:
                        pass
                try:
                    db.session.execute(text("UPDATE database SET role_badge_owner = 'bg-hot-pink' WHERE role_badge_owner IS NULL OR role_badge_owner = 'bg-danger'"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
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


@app.errorhandler(403)
def handle_forbidden(_err):
    flash("You cannot access that page.", "error")
    return redirect(url_for("index"))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = current_user
    if request.method == 'POST':
        user.name = (request.form.get('name') or '').strip()
        user.title = (request.form.get('title') or '').strip()
        user.phone = (request.form.get('phone') or '').strip()
        user.organization = (request.form.get('organization') or '').strip()
        user.bio = (request.form.get('bio') or '').strip()
        db.session.commit()
        flash('Profile updated.', 'ok')
        return redirect(url_for('edit_profile'))
    return render_template('profile.html', user=user)


@app.get('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    is_owner = bool(current_user.is_authenticated and current_user.id == user.id)
    return render_template('profile_view.html', user=user, is_owner=is_owner)

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
    time_zone = db.Column(db.String(64), default='UTC')
    role_badge_owner = db.Column(db.String(32), default='bg-hot-pink')
    role_badge_admin = db.Column(db.String(32), default='bg-primary')
    role_badge_editor = db.Column(db.String(32), default='bg-success')
    role_badge_viewer = db.Column(db.String(32), default='bg-secondary')

    # optional URL slug for nicer lab URLs
    slug = db.Column(db.String(160), nullable=True, unique=True)
    # optional per-lab database filename (relative to BASE_DIR)
    db_filename = db.Column(db.String(300), nullable=True, unique=True)

    owner = db.relationship("User")
    projects = db.relationship(
        "Project", backref="database", cascade="all, delete-orphan")

    @property
    def member_ids(self):
        """Return a list of user ids who are members of this lab.

        This is computed from DatabaseMember rows. The owner is expected
        to be included (the lab creation flow creates a DatabaseMember for
        the owner), but this property is authoritative regardless.
        """
        try:
            return [m.user_id for m in self.members]
        except Exception:
            return []

    @property
    def admin_ids(self):
        """Return a list of user ids who are admins (owner or admin role)."""
        try:
            return [m.user_id for m in self.members if m.role in ("owner", "admin")]
        except Exception:
            return []


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
    title = db.Column(db.String(120))
    phone = db.Column(db.String(64))
    organization = db.Column(db.String(160))
    bio = db.Column(db.Text)
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
    slug = db.Column(db.String(160), nullable=True)
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
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    uploaded_by = db.relationship("User")


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
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    uploaded_by = db.relationship("User")


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
    # lab scoping
    database_id = db.Column(db.Integer, db.ForeignKey('database.id'), nullable=True)
    database = db.relationship('Database')


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
    # optional lab scoping (nullable for legacy)
    database_id = db.Column(db.Integer, db.ForeignKey('database.id'), nullable=True)
    database = db.relationship('Database')
    # optional facility linkage
    facility_id = db.Column(db.Integer, db.ForeignKey('facility.id'), nullable=True)
    facility = db.relationship('Facility', foreign_keys=[facility_id])

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


class Facility(db.Model):
    __tablename__ = 'facility'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(160), nullable=True)
    location = db.Column(db.String(200))
    address_line1 = db.Column(db.String(200))
    address_line2 = db.Column(db.String(200))
    city = db.Column(db.String(120))
    state = db.Column(db.String(120))
    postal_code = db.Column(db.String(40))
    country = db.Column(db.String(120))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    manager_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    manager = db.relationship('User', foreign_keys=[manager_user_id])
    database_id = db.Column(db.Integer, db.ForeignKey('database.id'), nullable=True)
    database = db.relationship('Database')


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
    calibration_type = db.Column(db.String(120))
    values_json = db.Column(db.Text)   # JSON list of {"ref": <value>, "measured": <value>} or simple pairs
    temperature = db.Column(db.Float)
    summary_json = db.Column(db.Text)  # computed summary (bias, slope, r2, etc.) as JSON string
    next_due_date = db.Column(db.DateTime)

    equipment = db.relationship('Equipment', backref=db.backref('calibration_logs', cascade='all, delete-orphan'))


class CalibrationRoutine(db.Model):
    __tablename__ = 'calibration_routine'
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)  # type/name
    measurement = db.Column(db.String(120), nullable=False, default='')
    unit = db.Column(db.String(40))
    standard = db.Column(db.String(120))
    min_value = db.Column(db.Float)
    max_value = db.Column(db.Float)
    required_measurements = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    equipment = db.relationship('Equipment', backref=db.backref('calibration_routines', cascade='all, delete-orphan'))


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
    original_quantity = db.Column(db.Float)
    unit = db.Column(db.String(64))
    location = db.Column(db.String(200))
    manufacturer = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # optional link to a SampleClass (categorize stock materials)
    sample_class_id = db.Column(db.Integer, db.ForeignKey('sample_class.id'), nullable=True)
    sample_class = db.relationship('SampleClass', foreign_keys=[sample_class_id])
    # optional class attributes payload (JSON)
    class_attrs_json = db.Column(db.Text)
    # lab scoping
    database_id = db.Column(db.Integer, db.ForeignKey('database.id'), nullable=True)
    database = db.relationship('Database')
    documents = db.relationship('StockMaterialDocument', backref='stock_material', cascade='all, delete-orphan')
    quantity_logs = db.relationship('StockMaterialQuantityLog', backref='stock_material', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<StockMaterial {self.id} {self.name}>"


class StockMaterialDocument(db.Model):
    __tablename__ = 'stock_material_document'
    id = db.Column(db.Integer, primary_key=True)
    stock_material_id = db.Column(db.Integer, db.ForeignKey('stock_material.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(500), nullable=False)
    mimetype = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    uploaded_by = db.relationship("User")


class StockMaterialQuantityLog(db.Model):
    __tablename__ = 'stock_material_quantity_log'
    id = db.Column(db.Integer, primary_key=True)
    stock_material_id = db.Column(db.Integer, db.ForeignKey('stock_material.id'), nullable=False)
    sample_id = db.Column(db.Integer, db.ForeignKey('sample.id'), nullable=True)
    quantity_before = db.Column(db.Float, nullable=True)
    quantity_after = db.Column(db.Float, nullable=True)
    delta = db.Column(db.Float, nullable=True)
    note = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sample = db.relationship('Sample', foreign_keys=[sample_id])


class SampleStockMaterial(db.Model):
    __tablename__ = 'sample_stock_material'
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey('sample.id'), nullable=False)
    stock_material_id = db.Column(db.Integer, db.ForeignKey('stock_material.id'), nullable=False)
    quantity_used = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sample = db.relationship('Sample', backref=db.backref('stock_material_links', cascade='all, delete-orphan'))
    stock_material = db.relationship('StockMaterial')


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


class SampleLog(db.Model):
    __tablename__ = 'sample_log'
    id = db.Column(db.Integer, primary_key=True)
    sample_id = db.Column(db.Integer, db.ForeignKey('sample.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sample = db.relationship('Sample', backref=db.backref('logs', cascade='all, delete-orphan'))
    user = db.relationship('User')


class Invitation(db.Model):
    __tablename__ = 'invitation'
    id = db.Column(db.Integer, primary_key=True)
    database_id = db.Column(db.Integer, db.ForeignKey('database.id'), nullable=False)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invitee_email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), default='viewer')
    token = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accepted_at = db.Column(db.DateTime, nullable=True)
    accepted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    database = db.relationship('Database')
    inviter = db.relationship('User', foreign_keys=[inviter_id])
    accepter = db.relationship('User', foreign_keys=[accepted_by])




# --- Helpers ---
def set_current_lab(lab):
    try:
        if lab and (lab.slug or lab.id):
            session['current_lab_slug'] = lab.slug or str(lab.id)
    except Exception:
        pass


def get_lab_or_404(lab_slug: str):
    if not lab_slug:
        abort(404)
    lab = Database.query.filter_by(slug=lab_slug).first()
    if not lab and lab_slug.isdigit():
        lab = Database.query.get(int(lab_slug))
    if not lab:
        abort(404)

    # membership check: allow viewing if member or lab is public
    current_membership = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not current_membership and lab.default_visibility == VIS_PRIVATE:
        abort(403)
    return lab

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


def slugify_name(name: str) -> str:
    s = (name or '').strip().lower()
    s = re.sub(r"[^a-z0-9\-]+", '-', s)
    s = re.sub(r"-+", '-', s).strip('-')
    return s or None


def generate_facility_slug(name: str, lab_id: int, exclude_id: int = None) -> str:
    base = slugify_name(name)
    if not base:
        base = f"facility-{lab_id}-{int(datetime.utcnow().timestamp())}"
    slug = base
    i = 1
    while True:
        q = Facility.query.filter(
            Facility.database_id == lab_id,
            Facility.slug == slug
        )
        if exclude_id:
            q = q.filter(Facility.id != exclude_id)
        if not q.first():
            break
        slug = f"{base}-{i}"
        i += 1
    return slug


def _lab_timezone():
    slug = session.get('current_lab_slug')
    lab = None
    if slug:
        lab = Database.query.filter_by(slug=slug).first()
        if not lab and str(slug).isdigit():
            lab = Database.query.get(int(slug))
    tz_name = getattr(lab, 'time_zone', None) or 'UTC'
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return timezone.utc


def lab_dt(value, fmt='%m-%d-%Y %H:%M'):
    if not value:
        return ''
    tz = _lab_timezone()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(tz).strftime(fmt)


def lab_date(value, fmt='%m-%d-%Y'):
    return lab_dt(value, fmt)


app.jinja_env.filters['lab_dt'] = lab_dt
app.jinja_env.filters['lab_date'] = lab_date


def role_badge_class(role: str) -> str:
    role = (role or '').lower()
    slug = session.get('current_lab_slug')
    lab = None
    if slug:
        lab = Database.query.filter_by(slug=slug).first()
        if not lab and str(slug).isdigit():
            lab = Database.query.get(int(slug))
    if role == 'owner':
        return getattr(lab, 'role_badge_owner', None) or 'bg-hot-pink'
    if role == 'admin':
        return getattr(lab, 'role_badge_admin', None) or 'bg-primary'
    if role == 'editor':
        return getattr(lab, 'role_badge_editor', None) or 'bg-success'
    return getattr(lab, 'role_badge_viewer', None) or 'bg-secondary'


app.jinja_env.filters['role_badge'] = role_badge_class


def role_label(role: str) -> str:
    role = (role or '').lower()
    if role == 'admin':
        return 'manager'
    return role


app.jinja_env.filters['role_label'] = role_label


def role_for_user(user_id: int):
    slug = session.get('current_lab_slug')
    if not slug or not user_id:
        return None
    lab = Database.query.filter_by(slug=slug).first()
    if not lab and str(slug).isdigit():
        lab = Database.query.get(int(slug))
    if not lab:
        return None
    m = DatabaseMember.query.filter_by(database_id=lab.id, user_id=user_id).first()
    return m.role if m else None


app.jinja_env.globals['role_for_user'] = role_for_user


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
    # Nest experiment uploads under the lab folder: <UPLOAD_FOLDER>/<lab_key>/projects/<proj_key>/experiments/<experiment_id>
    proj = Project.query.get(project_id)
    if not proj:
        # fallback to legacy path
        d = os.path.join(UPLOAD_FOLDER, str(project_id), str(experiment_id))
        os.makedirs(d, exist_ok=True)
        return d

    dbobj = getattr(proj, 'database', None)
    lab_key = None
    if dbobj:
        lab_key = dbobj.slug or f"lab-{dbobj.id}"
    else:
        lab_key = 'lab-unknown'

    proj_key = f"{proj.id}-{safe_slug(proj.title)}"
    d = os.path.join(UPLOAD_FOLDER, lab_key, 'projects', proj_key, 'experiments', str(experiment_id))
    os.makedirs(d, exist_ok=True)
    return d


def sample_upload_dir(sample_id: int) -> str:
    # Nest sample uploads under the lab folder: <UPLOAD_FOLDER>/<lab_key>/projects/<proj_key>/samples/<sample_id>
    sample = Sample.query.get(sample_id)
    if not sample:
        d = os.path.join(UPLOAD_FOLDER, "samples", str(sample_id))
        os.makedirs(d, exist_ok=True)
        return d

    proj = getattr(sample, 'project', None)
    dbobj = getattr(proj, 'database', None) if proj else None
    lab_key = dbobj.slug or (f"lab-{dbobj.id}" if dbobj else 'lab-unknown')

    proj_key = f"{proj.id}-{safe_slug(proj.title)}" if proj else 'no-project'
    d = os.path.join(UPLOAD_FOLDER, lab_key, 'projects', proj_key, 'samples', str(sample_id))
    os.makedirs(d, exist_ok=True)
    return d


def stock_material_upload_dir(stock_id: int) -> str:
    mat = StockMaterial.query.get(stock_id)
    if not mat:
        d = os.path.join(UPLOAD_FOLDER, "stock-materials", str(stock_id))
        os.makedirs(d, exist_ok=True)
        return d

    dbobj = getattr(mat, 'database', None)
    lab_key = dbobj.slug or (f"lab-{dbobj.id}" if dbobj else 'lab-unknown')
    d = os.path.join(UPLOAD_FOLDER, lab_key, 'stock-materials', str(stock_id))
    os.makedirs(d, exist_ok=True)
    return d



def _lab_db_path(lab: Database):
    if not lab or not lab.db_filename:
        return None
    return os.path.join(BASE_DIR, lab.db_filename)


def _ensure_lab_timeline_table(path: str):
    if not path:
        return
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS lab_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            title TEXT,
            meta_json TEXT,
            actor_id INTEGER
        )
        """
    )
    conn.commit()
    conn.close()


def log_lab_event(lab: Database, event_type: str, entity_type: str, entity_id: int = None, title: str = None, meta: dict = None):
    path = _lab_db_path(lab)
    if not path:
        return
    _ensure_lab_timeline_table(path)
    try:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO lab_timeline (occurred_at, event_type, entity_type, entity_id, title, meta_json, actor_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                event_type,
                entity_type,
                entity_id,
                title,
                json.dumps(meta or {}),
                _uid(),
            )
        )
        conn.commit()
        conn.close()
    except Exception:
        try:
            conn and conn.close()
        except Exception:
            pass


def fetch_lab_events(lab: Database, event_types=None, entity_types=None):
    path = _lab_db_path(lab)
    if not path or not os.path.exists(path):
        return []
    _ensure_lab_timeline_table(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT occurred_at, event_type, entity_type, entity_id, title, meta_json, actor_id FROM lab_timeline ORDER BY occurred_at DESC")
    rows = cur.fetchall()
    conn.close()

    out = []
    for r in rows:
        ev = {
            "occurred_at": r[0],
            "event_type": r[1],
            "entity_type": r[2],
            "entity_id": r[3],
            "title": r[4],
            "meta": safe_json_loads(r[5], {}),
            "actor_id": r[6],
        }
        if event_types and ev["event_type"] not in event_types:
            continue
        if entity_types and ev["entity_type"] not in entity_types:
            continue
        out.append(ev)
    return out


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
    Create a SampleExperiment link for the selected experiment only.
    Avoids duplicate links.
    """
    exists = SampleExperiment.query.filter_by(
        sample_id=sample.id, experiment_id=selected_exp.id, role=role
    ).first()
    if not exists:
        db.session.add(SampleExperiment(
            sample_id=sample.id,
            experiment_id=selected_exp.id,
            role=role,
            notes=notes
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
    # Show labs the current user is a member of and allow creating a new lab
    labs = []
    if current_user.is_authenticated:
        try:
            labs = (Database.query
                    .join(DatabaseMember, DatabaseMember.database_id == Database.id)
                    .filter(DatabaseMember.user_id == current_user.id)
                    .order_by(Database.name.asc())
                    .all())
        except OperationalError:
            # attempt runtime migration and retry
            try:
                ensure_runtime_columns_once()
            except Exception:
                pass
            labs = (Database.query
                    .join(DatabaseMember, DatabaseMember.database_id == Database.id)
                    .filter(DatabaseMember.user_id == current_user.id)
                    .order_by(Database.name.asc())
                    .all())

        # incoming invitations addressed to this user's email
        try:
            incoming_invites = Invitation.query.filter_by(invitee_email=(current_user.email or '').lower(), accepted_at=None).all()
        except Exception:
            incoming_invites = []
    else:
        incoming_invites = []

    return render_template('index.html', labs=labs, incoming_invites=incoming_invites)


@app.route('/projects/all')
def all_projects():
    # Require lab context; redirect to lab-specific view
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('all_projects_for_lab', lab_slug=slug))
    flash('Select a lab to view projects.', 'error')
    return redirect(url_for('index'))


@app.route('/lab/<lab_slug>/projects')
def all_projects_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    lab_role = db_role(current_user, lab.id)
    try:
        lab_members = (User.query
                       .join(DatabaseMember, DatabaseMember.user_id == User.id)
                       .filter(DatabaseMember.database_id == lab.id)
                       .order_by(User.name.asc())
                       .all())
    except Exception:
        lab_members = []
    try:
        today = datetime.utcnow().date()
        # Current projects: have a start_date and no end_date set
        current = (Project.query
                   .filter(Project.database_id == lab.id, Project.start_date != None, Project.end_date == None)
                   .order_by(Project.start_date.asc())
                   .all())
        # Archive: end_date set and before today
        archive = (Project.query
                   .filter(Project.database_id == lab.id, Project.end_date != None, Project.end_date < today)
                   .order_by(Project.end_date.desc())
                   .all())
    except OperationalError as e:
        app.logger.warning('OperationalError querying Projects list, attempting runtime migration: %s', e)
        try:
            add_column_if_missing('project', 'start_date', 'DATE')
            add_column_if_missing('project', 'end_date', 'DATE')
        except Exception:
            pass
        # retry
        today = datetime.utcnow().date()
        current = (Project.query
                   .filter(Project.database_id == lab.id, Project.start_date != None, Project.end_date == None)
                   .order_by(Project.start_date.asc())
                   .all())
        archive = (Project.query
                   .filter(Project.database_id == lab.id, Project.end_date != None, Project.end_date < today)
                   .order_by(Project.end_date.desc())
                   .all())

    return render_template('all_projects.html', current=current, archive=archive, current_lab=lab, lab_role=lab_role, lab_members=lab_members)


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

    min_date = datetime(2020, 1, 1).date()
    if project.start_date and project.start_date < min_date:
        flash('Start date cannot be before 2020.', 'error')
        return redirect(url_for('view_project', project_id=project.id))
    if project.end_date and project.end_date < min_date:
        flash('End date cannot be before 2020.', 'error')
        return redirect(url_for('view_project', project_id=project.id))
    if project.start_date and project.end_date and project.end_date < project.start_date:
        flash('End date must be after start date.', 'error')
        return redirect(url_for('view_project', project_id=project.id))

    db.session.commit()
    flash('Project dates updated.', 'ok')
    return redirect(url_for('view_project', project_id=project.id))


@app.post('/project/<int:project_id>/slug')
@app.post('/lab/<lab_slug>/project/<int:project_id>/slug')
@login_required
def update_project_slug(project_id, lab_slug=None):
    project = Project.query.get_or_404(project_id)
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if project.database_id != lab.id:
            abort(403)
        set_current_lab(lab)

    if not can_manage_project(project):
        abort(403)

    raw = (request.form.get('slug') or '').strip()
    if not raw:
        project.slug = None
        db.session.commit()
        flash('Project slug cleared.', 'ok')
        return redirect(url_for('view_project', project_id=project.id))

    def _slugify(s: str) -> str:
        s = s.lower()
        s = re.sub(r"[^a-z0-9\-]+", '-', s)
        s = re.sub(r"-+", '-', s).strip('-')
        return s

    normalized = _slugify(raw)
    if normalized != raw:
        flash('Slug must use lowercase letters, numbers, and hyphens only.', 'error')
        return redirect(url_for('view_project', project_id=project.id))

    existing = Project.query.filter(
        Project.database_id == project.database_id,
        Project.slug == normalized,
        Project.id != project.id
    ).first()
    if existing:
        flash('That slug is already used by another project in this lab.', 'error')
        return redirect(url_for('view_project', project_id=project.id))

    project.slug = normalized
    db.session.commit()
    flash('Project slug updated.', 'ok')
    return redirect(url_for('view_project', project_id=project.id))


@app.post('/project/<int:project_id>/delete')
@app.post('/lab/<lab_slug>/project/<int:project_id>/delete')
def delete_project(project_id, lab_slug=None):
    project = Project.query.get_or_404(project_id)

    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if project.database_id != lab.id:
            abort(403)
        set_current_lab(lab)

    if not can_manage_project(project):
        abort(403)

    lab = project.database
    try:
        db.session.delete(project)
        db.session.commit()
        flash('Project deleted.', 'ok')
    except Exception:
        db.session.rollback()
        flash('Failed to delete project.', 'error')
        return redirect(url_for('view_project', project_id=project.id))

    if lab:
        lab_key = lab.slug or str(lab.id)
        return redirect(url_for('all_projects_for_lab', lab_slug=lab_key))
    return redirect(url_for('index'))


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

    sc = SampleClass.query.get(sample_class_id)
    if not sc or sc.database_id != project.database_id:
        flash('Selected Sample Class is not part of this lab.', 'error')
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
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('api_project_class_attrs_for_lab', lab_slug=slug, project_id=project_id, class_id=class_id))
    return jsonify([])


@app.route('/lab/<lab_slug>/api/project/<int:project_id>/sample-class/<int:class_id>/attrs')
def api_project_class_attrs_for_lab(lab_slug, project_id, class_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    project = Project.query.get_or_404(project_id)
    if project.database_id != lab.id:
        abort(403)
    # Return merged attributes: lab-level class attrs overridden/extended by project-specific attrs
    sc = SampleClass.query.get_or_404(class_id)
    if sc.database_id != lab.id:
        abort(403)
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
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('api_project_sample_attrs_for_lab', lab_slug=slug, project_id=project_id))
    return jsonify([])


@app.route("/lab/<lab_slug>/api/project/<int:project_id>/sample-attrs")
def api_project_sample_attrs_for_lab(lab_slug, project_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    project = Project.query.get_or_404(project_id)
    if project.database_id != lab.id:
        abort(403)
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
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('api_sample_attr_values_for_lab', lab_slug=slug, sample_id=sample_id))
    return jsonify({})


@app.route('/lab/<lab_slug>/api/sample/<int:sample_id>/attr-values')
def api_sample_attr_values_for_lab(lab_slug, sample_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    s = Sample.query.get_or_404(sample_id)
    if not s.project or s.project.database_id != lab.id:
        abort(403)
    root = get_sample_root(s)
    vals = SampleAttributeValue.query.filter_by(sample_id=root.id).all()
    out = {str(v.attribute_id): v.value for v in vals}
    return jsonify(out)


@app.route('/api/geo/countries')
@login_required
def api_geo_countries():
    countries = []
    try:
        for c in pycountry.countries:
            code = getattr(c, 'alpha_2', None) or getattr(c, 'alpha_3', None)
            if not code:
                continue
            countries.append({'code': code, 'name': c.name})
    except Exception:
        countries = []
    countries.sort(key=lambda x: x['name'])
    return jsonify(countries)


@app.route('/api/geo/subdivisions')
@login_required
def api_geo_subdivisions():
    country = (request.args.get('country') or '').strip().upper()
    subdivisions = []
    if country:
        try:
            subs = pycountry.subdivisions.get(country_code=country)
            for s in subs:
                code = s.code.split('-', 1)[-1] if s.code else s.name
                subdivisions.append({'code': code, 'name': s.name})
        except Exception:
            subdivisions = []
    subdivisions.sort(key=lambda x: x['name'])
    return jsonify(subdivisions)

# ---- Projects ----


@app.route("/projects/create", methods=["POST"])
def create_project():
    slug = session.get('current_lab_slug')
    if not slug:
        flash('Select a lab before creating a project.', 'error')
        return redirect(url_for('index'))

    lab = Database.query.filter_by(slug=slug).first()
    if not lab and str(slug).isdigit():
        lab = Database.query.get(int(slug))
    if not lab:
        flash('Lab not found.', 'error')
        return redirect(url_for('index'))

    member = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not member or member.role not in ('owner', 'admin', 'editor'):
        abort(403)

    title = request.form.get("title", "").strip()
    desc = request.form.get("description", "").strip()
    pi_user_id = request.form.get("pi_user_id", type=int)
    if not title:
        flash("Project title is required.", "error")
        if lab.slug:
            return redirect(url_for('view_lab_by_slug', slug=lab.slug))
        return redirect(url_for('view_lab', db_id=lab.id))

    project = Project(title=title, description=desc, creator_id=_uid(), database_id=lab.id)
    if pi_user_id:
        member_ids = {m.user_id for m in DatabaseMember.query.filter_by(database_id=lab.id).all()}
        if pi_user_id in member_ids:
            project.pi_user_id = pi_user_id
    db.session.add(project)
    db.session.commit()
    log_lab_event(lab, "created", "project", project.id, project.title)
    return redirect(url_for("view_project", project_id=project.id))


@app.post('/labs/create')
@login_required
def create_lab():
    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Lab name is required.', 'error')
        return redirect(url_for('index'))

    def slugify(s):
        s = s.lower()
        s = re.sub(r"[^a-z0-9\-]+", '-', s)
        s = re.sub(r"-+", '-', s).strip('-')
        return s or None

    # Prevent duplicate lab names
    existing_name = Database.query.filter_by(name=name).first()
    if existing_name:
        flash('A lab with that name already exists. Choose a different name.', 'error')
        return redirect(url_for('index'))

    base = slugify(name)
    # If slugify removed all characters (e.g. name contains only symbols), fall back to a safe base
    if not base:
        base = f"lab-{current_user.id}-{int(datetime.utcnow().timestamp())}"

    # Ensure slug uniqueness
    slug = base
    i = 1
    while Database.query.filter_by(slug=slug).first():
        slug = f"{base}-{i}"
        i += 1

    db_obj = Database(name=name, owner_id=current_user.id, slug=slug)
    db.session.add(db_obj)
    try:
        db.session.flush()  # get id
        # create per-lab sqlite file and initialize schema for lab-scoped tables
        lab_db_filename = os.path.join('Labs', f"{slug}.db")
        lab_db_path = os.path.join(BASE_DIR, lab_db_filename)
        # ensure unique filename if exists
        j = 1
        base_path = lab_db_path
        while os.path.exists(lab_db_path):
            lab_db_path = os.path.join(BASE_DIR, 'Labs', f"{slug}-{j}.db")
            lab_db_filename = os.path.join('Labs', f"{slug}-{j}.db")
            j += 1
        # create empty file
        open(lab_db_path, 'a').close()
        # create selected tables in the lab DB (exclude backend tables)
        engine = create_engine(f"sqlite:///{lab_db_path}")
        exclude = set(['database', 'database_member', 'user', 'invitation'])
        for tbl_name, tbl in db.metadata.tables.items():
            if tbl_name in exclude:
                continue
            try:
                tbl.create(bind=engine, checkfirst=True)
            except Exception:
                pass
        db_obj.db_filename = lab_db_filename
        member = DatabaseMember(database_id=db_obj.id, user_id=current_user.id, role='owner')
        db.session.add(member)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Failed to create lab due to a database constraint (possible duplicate). Try a different name.', 'error')
        return redirect(url_for('index'))

    flash('Lab created.', 'ok')
    if db_obj.slug:
        return redirect(url_for('view_lab_by_slug', slug=db_obj.slug))
    return redirect(url_for('view_lab', db_id=db_obj.id))


@app.route('/lab/<int:db_id>')
@login_required
def view_lab(db_id):
    lab = Database.query.get_or_404(db_id)
    # membership check: allow viewing if member or lab is public
    current_membership = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not current_membership and lab.default_visibility == VIS_PRIVATE:
        abort(403)

    set_current_lab(lab)

    projects = Project.query.filter_by(database_id=lab.id).order_by(Project.created_at.desc()).all()
    facilities = Facility.query.filter_by(database_id=lab.id).order_by(Facility.name.asc()).all()
    can_manage = bool(current_membership and current_membership.role in ("owner", "admin"))
    is_owner = bool(current_membership and current_membership.role == "owner")
    lab_members = lab.members if lab else []
    return render_template('lab_home.html', current_lab=lab, projects=projects, facilities=facilities, can_manage=can_manage, is_owner=is_owner, lab_members=lab_members)


@app.route('/lab/slug/<slug>')
@login_required
def view_lab_by_slug(slug):
    lab = Database.query.filter_by(slug=slug).first_or_404()
    current_membership = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not current_membership and lab.default_visibility == VIS_PRIVATE:
        abort(403)
    set_current_lab(lab)
    projects = Project.query.filter_by(database_id=lab.id).order_by(Project.created_at.desc()).all()
    facilities = Facility.query.filter_by(database_id=lab.id).order_by(Facility.name.asc()).all()
    can_manage = bool(current_membership and current_membership.role in ("owner", "admin"))
    is_owner = bool(current_membership and current_membership.role == "owner")
    lab_members = lab.members if lab else []
    return render_template('lab_home.html', current_lab=lab, projects=projects, facilities=facilities, can_manage=can_manage, is_owner=is_owner, lab_members=lab_members)


@app.post('/lab/<lab_slug>/settings/timezone')
@login_required
def update_lab_timezone(lab_slug):
    lab = get_lab_or_404(lab_slug)
    role = db_role(current_user, lab.id)
    if role != 'owner':
        abort(403)
    tz = (request.form.get('time_zone') or '').strip() or 'UTC'
    try:
        ZoneInfo(tz)
    except Exception:
        flash('Time zone saved, but tzdata is missing on this system. Times will display in UTC until tzdata is installed.', 'warning')
    lab.time_zone = tz
    db.session.commit()
    flash('Lab time zone updated.', 'ok')
    return redirect(url_for('view_lab_by_slug', slug=lab.slug) if lab.slug else url_for('view_lab', db_id=lab.id))


@app.route('/lab/<lab_slug>/timeline')
@login_required
def lab_timeline(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)

    types_list = request.args.getlist('types')
    entities_list = request.args.getlist('entities')
    if not types_list:
        types_param = (request.args.get('types') or '').strip()
        types_list = [t.strip() for t in types_param.split(',') if t.strip()]
    if not entities_list:
        entities_param = (request.args.get('entities') or '').strip()
        entities_list = [t.strip() for t in entities_param.split(',') if t.strip()]
    event_types = set(types_list) if types_list else None
    entity_types = set(entities_list) if entities_list else None

    events = fetch_lab_events(lab, event_types=event_types, entity_types=entity_types)

    grouped = {}
    for ev in events:
        ts = ev.get('occurred_at') or ''
        key = ts[:7] if len(ts) >= 7 else 'unknown'
        grouped.setdefault(key, []).append(ev)
    for k in grouped:
        grouped[k].sort(key=lambda x: x.get('occurred_at', ''), reverse=True)

    return render_template(
        'lab_timeline.html',
        current_lab=lab,
        grouped=grouped,
        selected_types=event_types or set(),
        selected_entities=entity_types or set(),
    )


@app.route('/lab/<int:db_id>/members')
@login_required
def lab_members_api(db_id):
    """Return JSON with lists of member user ids and admin user ids for a lab.

    Only lab members (or if the lab is public) may retrieve this listing.
    """
    lab = Database.query.get_or_404(db_id)
    is_member = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not is_member and lab.default_visibility == VIS_PRIVATE:
        abort(403)

    return jsonify({
        'members': lab.member_ids,
        'admins': lab.admin_ids,
    })



@app.post('/lab/<int:db_id>/members/add')
@login_required
def lab_members_add(db_id):
    """Invite or add a user to the lab by email. Only owners/admins may add."""
    lab = Database.query.get_or_404(db_id)
    actor = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not (actor and actor.role in ("owner", "admin")):
        abort(403)

    email = (request.form.get('email') or '').strip().lower()
    role = (request.form.get('role') or 'viewer').strip()
    if not email:
        flash('Email is required to invite a member.', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    user = User.query.filter_by(email=email).first()
    if user:
        existing = DatabaseMember.query.filter_by(database_id=lab.id, user_id=user.id).first()
        if existing:
            flash('User is already a member of this lab.', 'info')
            return redirect(url_for('view_lab', db_id=lab.id))

    pending = Invitation.query.filter_by(database_id=lab.id, invitee_email=email, accepted_at=None).first()
    if pending:
        flash('An invitation is already pending for this user.', 'info')
        return redirect(url_for('view_lab', db_id=lab.id))

    # Create a pending invitation for this email address
    try:
        inv = Invitation(database_id=lab.id, inviter_id=_uid(), invitee_email=email, role=role)
        db.session.add(inv)
        db.session.commit()
        flash(f'Invitation sent to {email}.', 'ok')
    except Exception:
        db.session.rollback()
        flash('Failed to create invitation.', 'error')
    return redirect(url_for('view_lab', db_id=lab.id))


@app.post('/lab/<int:db_id>/members/remove')
@login_required
def lab_members_remove(db_id):
    """Remove a member from the lab. Owners cannot be removed via this endpoint."""
    lab = Database.query.get_or_404(db_id)
    actor = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not (actor and actor.role in ("owner", "admin")):
        abort(403)

    user_id = request.form.get('user_id')
    if not user_id:
        flash('user_id required', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    try:
        uid = int(user_id)
    except Exception:
        flash('Invalid user id', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    member = DatabaseMember.query.filter_by(database_id=lab.id, user_id=uid).first()
    if not member:
        flash('Member not found', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    if member.role == 'owner':
        flash('Cannot remove the owner via this action. Transfer ownership first.', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    db.session.delete(member)
    db.session.commit()
    flash('Member removed.', 'ok')
    return redirect(url_for('view_lab', db_id=lab.id))


@app.post('/lab/<int:db_id>/members/change-role')
@login_required
def lab_members_change_role(db_id):
    """Change a member's role. Only owners may promote to owner; admins may change other roles."""
    lab = Database.query.get_or_404(db_id)
    actor = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not actor:
        abort(403)

    target_id = request.form.get('user_id')
    new_role = (request.form.get('role') or '').strip()
    if not target_id or not new_role:
        flash('user_id and role are required.', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    try:
        tid = int(target_id)
    except Exception:
        flash('Invalid user id', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    target = DatabaseMember.query.filter_by(database_id=lab.id, user_id=tid).first()
    if not target:
        flash('Target member not found.', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    # If trying to set owner, require the actor to be owner
    if new_role == 'owner' and actor.role != 'owner':
        flash('Only an owner may promote someone to owner.', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))

    # Prevent demoting the only owner
    if target.role == 'owner' and new_role != 'owner':
        other_owner = DatabaseMember.query.filter(DatabaseMember.database_id == lab.id, DatabaseMember.user_id != target.user_id, DatabaseMember.role == 'owner').first()
        if not other_owner:
            flash('Cannot demote the only owner. Transfer ownership first.', 'error')
            return redirect(url_for('view_lab', db_id=lab.id))

    target.role = new_role
    db.session.commit()
    flash('Member role updated.', 'ok')
    return redirect(url_for('view_lab', db_id=lab.id))


@app.post('/invites/<int:inv_id>/accept')
@login_required
def invite_accept(inv_id):
    inv = Invitation.query.get_or_404(inv_id)
    if inv.accepted_at:
        flash('Invitation already handled.', 'info')
        return redirect(url_for('index'))

    if current_user.email.lower() != inv.invitee_email.lower():
        abort(403)

    # add member if not already
    existing = DatabaseMember.query.filter_by(database_id=inv.database_id, user_id=current_user.id).first()
    try:
        if not existing:
            member = DatabaseMember(database_id=inv.database_id, user_id=current_user.id, role=inv.role or 'viewer')
            db.session.add(member)
        inv.accepted_at = datetime.utcnow()
        inv.accepted_by = current_user.id
        db.session.commit()
        flash(f'You have joined {inv.database.name}.', 'ok')
    except Exception:
        db.session.rollback()
        flash('Failed to accept invitation.', 'error')

    return redirect(url_for('view_lab', db_id=inv.database_id))


@app.post('/invites/<int:inv_id>/decline')
@login_required
def invite_decline(inv_id):
    inv = Invitation.query.get_or_404(inv_id)
    if current_user.email.lower() != inv.invitee_email.lower():
        abort(403)
    try:
        db.session.delete(inv)
        db.session.commit()
        flash('Invitation declined.', 'info')
    except Exception:
        db.session.rollback()
        flash('Failed to decline invitation.', 'error')
    return redirect(url_for('index'))


@app.post('/lab/<int:db_id>/projects/create')
@login_required
def create_project_for_lab(db_id):
    lab = Database.query.get_or_404(db_id)
    set_current_lab(lab)
    member = DatabaseMember.query.filter_by(database_id=lab.id, user_id=_uid()).first()
    if not member or member.role not in ('owner', 'admin', 'editor'):
        abort(403)
    title = (request.form.get('title') or '').strip()
    desc = (request.form.get('description') or '').strip()
    if not title:
        flash('Project title is required.', 'error')
        return redirect(url_for('view_lab', db_id=lab.id))
    project = Project(title=title, description=desc, creator_id=_uid(), database_id=lab.id)
    db.session.add(project)
    db.session.commit()
    log_lab_event(lab, "created", "project", project.id, project.title)
    flash('Project created.', 'ok')
    return redirect(url_for('view_project', project_id=project.id))


@app.post('/lab/<int:db_id>/delete')
@login_required
def delete_lab(db_id):
    """Delete a lab: remove backend metadata and optionally remove the per-lab DB file.

    Only the owner may delete a lab. This will remove the Database row and
    cascade-delete related backend-stored content (projects, samples, experiments)
    that are stored in the backend DB.
    """
    lab = Database.query.get_or_404(db_id)
    # only owner may delete
    if lab.owner_id != _uid():
        abort(403)

    # remember file path to remove
    relpath = lab.db_filename
    try:
        db.session.delete(lab)
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash('Failed to delete lab from backend database.', 'error')
        return redirect(url_for('view_lab', db_id=db_id))

    # remove per-lab DB file if present
    if relpath:
        try:
            full = os.path.join(BASE_DIR, relpath)
            if os.path.exists(full):
                os.remove(full)
        except Exception:
            # non-fatal
            pass

    flash('Lab deleted.', 'ok')
    return redirect(url_for('index'))


@app.route("/project/<int:project_id>")
@app.route("/lab/<lab_slug>/project/<int:project_id>")
def view_project(project_id, lab_slug=None):
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

    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if project.database_id != lab.id:
            abort(403)
        set_current_lab(lab)
    else:
        # enforce lab-prefixed access
        if project.database:
            lab_key = project.database.slug or str(project.database.id)
            return redirect(url_for('view_project', lab_slug=lab_key, project_id=project.id))

    sorted_experiments = sorted(
        project.experiments or [],
        key=lambda e: (e.start_at or datetime.min),
    )

    def _avg_measured_for_log(log):
        vals = safe_json_loads(log.values_json, [])
        measured = []
        if isinstance(vals, list):
            for item in vals:
                if isinstance(item, dict) and item.get('measured') is not None:
                    measured.append(item.get('measured'))
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    measured.append(item[1])
        if not measured:
            return None
        try:
            return sum(measured) / len(measured)
        except Exception:
            return None

    def _experiment_equipment_flags(exp):
        start_at = getattr(exp, 'start_at', None)
        end_at = getattr(exp, 'end_at', None) or start_at
        if not start_at:
            return []
        flags = []
        for link in getattr(exp, 'equipment_links', []) or []:
            eq = getattr(link, 'equipment', None)
            if not eq:
                continue
            routines = CalibrationRoutine.query.filter_by(equipment_id=eq.id).all()
            routine_map = {r.name: r for r in routines}
            logs = (CalibrationLog.query
                    .filter_by(equipment_id=eq.id)
                    .filter(CalibrationLog.performed_at.isnot(None))
                    .order_by(CalibrationLog.performed_at.asc())
                    .all())

            def _is_out_of_tolerance(log):
                if not log:
                    return False, None
                avg = _avg_measured_for_log(log)
                if avg is None:
                    return False, None
                routine = routine_map.get(log.calibration_type or 'default')
                if not routine:
                    return False, None
                if routine.min_value is not None and avg < routine.min_value:
                    return True, f"{avg:.4g} < min {routine.min_value}"
                if routine.max_value is not None and avg > routine.max_value:
                    return True, f"{avg:.4g} > max {routine.max_value}"
                return False, None

            start_logs = {}
            end_logs = {}
            after_logs = {}
            for l in logs:
                cal_type = l.calibration_type or 'default'
                if l.performed_at <= start_at:
                    start_logs[cal_type] = l
                if l.performed_at <= end_at:
                    end_logs[cal_type] = l
                if l.performed_at > end_at and cal_type not in after_logs:
                    after_logs[cal_type] = l

            tol_reasons = []
            cal_types = set(routine_map.keys()) | set(start_logs.keys()) | set(end_logs.keys()) | set(after_logs.keys())
            for cal_type in sorted(cal_types):
                start_log = start_logs.get(cal_type)
                end_log = end_logs.get(cal_type)
                next_after_end = after_logs.get(cal_type)

                out, reason = _is_out_of_tolerance(start_log)
                if out and start_log:
                    tol_reasons.append(f"{cal_type}: Start check ({start_log.performed_at.date()}): {reason}")
                out, reason = _is_out_of_tolerance(end_log)
                if out and end_log:
                    tol_reasons.append(f"{cal_type}: End check ({end_log.performed_at.date()}): {reason}")
                out, reason = _is_out_of_tolerance(next_after_end)
                if out and next_after_end:
                    tol_reasons.append(f"{cal_type}: After end ({next_after_end.performed_at.date()}): {reason}")

                if not next_after_end:
                    tol_reasons.append(f"{cal_type}: No calibration after experiment end")

            if not tol_reasons:
                for l in logs:
                    if l.performed_at < start_at or l.performed_at > end_at:
                        continue
                    out, reason = _is_out_of_tolerance(l)
                    if out:
                        tol_reasons.append(f"{l.calibration_type or 'default'}: During ({l.performed_at.date()}): {reason}")
                        break

            # calibration schedule check
            cal_reason = None
            if getattr(eq, 'calibration_interval_days', None):
                last_cal = (CalibrationLog.query
                            .filter_by(equipment_id=eq.id)
                            .filter(CalibrationLog.performed_at <= end_at)
                            .order_by(CalibrationLog.performed_at.desc())
                            .first())
                if not last_cal or not last_cal.performed_at:
                    cal_reason = 'No calibration on record'
                else:
                    due = last_cal.performed_at + timedelta(days=eq.calibration_interval_days)
                    if due < start_at:
                        cal_reason = f'Out of calibration before start ({due.date()})'
                    elif due < end_at:
                        cal_reason = f'Out of calibration during experiment ({due.date()})'
            # collect
            reasons = []
            categories = []
            if tol_reasons:
                reasons.extend(tol_reasons)
                categories.append('tolerance')
            if cal_reason:
                reasons.append(cal_reason)
                categories.append('calibration')
            if reasons:
                flags.append({
                    'equipment_id': eq.id,
                    'equipment_name': eq.name,
                    'reasons': reasons,
                    'categories': categories,
                    'url': url_for('view_equipment', lab_slug=(project.database.slug or project.database.id), equipment_id=eq.id) if project and project.database else url_for('view_equipment', equipment_id=eq.id),
                })
        return flags

    experiment_negative_flags = {}
    for exp in sorted_experiments:
        flags = _experiment_equipment_flags(exp)
        if flags:
            labels = []
            for f in flags:
                labels.append(f"{f['equipment_name']}: {', '.join(f['reasons'])}")
            experiment_negative_flags[exp.id] = {
                'label': '; '.join(labels),
                'flags': flags,
            }

    roots = (Sample.query
             .filter_by(project_id=project.id, parent_id=None)
             .order_by(Sample.name.asc())
             .all())
    sample_tree = [serialize_sample_tree(r) for r in roots]
    sample_tree_by_class = {}
    for r in roots:
        stock_obj = getattr(r, 'stock_material', None)
        sc = getattr(r, 'sample_class', None) or (getattr(stock_obj, 'sample_class', None) if stock_obj else None)
        class_label = sc.name if sc else 'No Sample Class'
        class_key = f"class:{sc.id}" if sc else 'noclass'
        class_entry = sample_tree_by_class.setdefault(class_key, {
            'label': class_label,
            'class_id': sc.id if sc else None,
            'stocks': {}
        })

        if stock_obj:
            stock_label = stock_obj.name + (f" — {stock_obj.lot_number}" if stock_obj.lot_number else "")
            stock_key = f"stock:{stock_obj.id}"
            stock_entry = class_entry['stocks'].setdefault(stock_key, {
                'label': stock_label,
                'stock_id': stock_obj.id,
                'roots': []
            })
            stock_entry['roots'].append(serialize_sample_tree(r))
        else:
            stock_key = 'nostock'
            stock_entry = class_entry['stocks'].setdefault(stock_key, {
                'label': 'No Stock Material',
                'stock_id': None,
                'roots': []
            })
            stock_entry['roots'].append(serialize_sample_tree(r))

    # sort class groups (No Sample Class last) and stock groups (No Stock Material last)
    sample_tree_by_class = dict(sorted(
        sample_tree_by_class.items(),
        key=lambda kv: (kv[1]['label'] == 'No Sample Class', kv[1]['label'].lower())
    ))
    for key, entry in sample_tree_by_class.items():
        entry['stocks'] = dict(sorted(
            entry['stocks'].items(),
            key=lambda kv: (kv[1]['label'] == 'No Stock Material', kv[1]['label'].lower())
        ))

    # PI candidates (prefer lab members)
    try:
        pi_candidates = get_db_members_for_project(project)
        if not pi_candidates:
            pi_candidates = User.query.order_by(User.name.asc()).all()
    except Exception:
        pi_candidates = get_db_members_for_project(project)
    can_manage = can_manage_project(project)
    lab_role = db_role(current_user, project.database_id)

    # sample class options (lab-level) and project-specific sample classes
    sample_classes = SampleClass.query.filter_by(database_id=project.database_id).order_by(SampleClass.name.asc()).all()
    project_sample_classes = ProjectSampleClass.query.filter_by(project_id=project.id).all()

    experiment_opts = [
        {"id": e.id, "title": e.title, "project_id": e.project_id}
        for e in Experiment.query.filter_by(project_id=project.id).order_by(Experiment.created_at.desc()).all()
    ]
    sample_opts = [
        {"id": s.id, "name": s.name, "project_id": s.project_id, "stock_material_id": (s.stock_material_id if hasattr(s, 'stock_material_id') else None)}
        for s in Sample.query.filter_by(project_id=project.id).order_by(Sample.created_at.desc()).all()
    ]
    sc_name_map = {sc.id: sc.name for sc in sample_classes}
    stock_material_opts = [
        {
            "id": m.id,
            "name": m.name,
            "lot_number": m.lot_number,
            "quantity": m.quantity,
            "unit": m.unit,
            "class_attrs": safe_json_loads(getattr(m, 'class_attrs_json', None), {}),
            "sample_class_id": getattr(m, 'sample_class_id', None),
            "sample_class_name": sc_name_map.get(getattr(m, 'sample_class_id', None))
        }
        for m in StockMaterial.query.filter_by(database_id=project.database_id).order_by(StockMaterial.name.asc()).all()
    ]

    return render_template(
        "project.html",
        project=project,
        sorted_experiments=sorted_experiments,
        experiment_negative_flags=experiment_negative_flags,
        sample_tree=sample_tree,
        sample_tree_by_class=sample_tree_by_class,
        pi_candidates=pi_candidates,
        lab_members=pi_candidates,
        lab_role=lab_role,
        can_manage=can_manage,
        sample_classes=sample_classes,
        project_sample_classes=project_sample_classes,
        experiment_opts=experiment_opts,
        sample_opts=sample_opts,
        stock_material_opts=stock_material_opts,
        current_lab=project.database,
    )


@app.route('/project/<int:project_id>/timeline')
@app.route('/lab/<lab_slug>/project/<int:project_id>/timeline')
def project_timeline(project_id, lab_slug=None):
    """Return timeline events for the project grouped by year-month.
    Events returned include experiments (start/end/created), sample creations,
    maintenance and calibration entries for equipment used in project experiments,
    measurements, documents and experiment logs.
    """
    project = Project.query.get_or_404(project_id)
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if project.database_id != lab.id:
            abort(403)
        set_current_lab(lab)
    else:
        if project.database:
            lab_key = project.database.slug or str(project.database.id)
            return redirect(url_for('project_timeline', lab_slug=lab_key, project_id=project.id))
    events = []

    # project start/end dates
    if project.start_date:
        events.append({
            'type': 'project_start',
            'timestamp': project.start_date.isoformat(),
            'title': project.title,
            'id': project.id,
            'url': url_for('view_project', lab_slug=lab.slug, project_id=project.id) if lab_slug else url_for('view_project', project_id=project.id)
        })
    if project.end_date:
        events.append({
            'type': 'project_end',
            'timestamp': project.end_date.isoformat(),
            'title': project.title,
            'id': project.id,
            'url': url_for('view_project', lab_slug=lab.slug, project_id=project.id) if lab_slug else url_for('view_project', project_id=project.id)
        })

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


@app.route('/experiment/<int:experiment_id>/timeline')
@app.route('/lab/<lab_slug>/experiment/<int:experiment_id>/timeline')
def experiment_timeline(experiment_id, lab_slug=None):
    exp = Experiment.query.get_or_404(experiment_id)
    project = exp.project
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if not project or project.database_id != lab.id:
            abort(403)
        set_current_lab(lab)
    else:
        if project and project.database:
            lab_key = project.database.slug or str(project.database.id)
            return redirect(url_for('experiment_timeline', lab_slug=lab_key, experiment_id=exp.id))

    events = []
    if exp.created_at:
        events.append({
            'type': 'created',
            'timestamp': exp.created_at.isoformat(),
            'title': exp.title,
            'id': exp.id,
            'url': url_for('view_experiment', experiment_id=exp.id)
        })
    if getattr(exp, 'start_at', None):
        events.append({
            'type': 'start',
            'timestamp': exp.start_at.isoformat(),
            'title': exp.title,
            'id': exp.id,
            'url': url_for('view_experiment', experiment_id=exp.id)
        })
    if getattr(exp, 'end_at', None):
        events.append({
            'type': 'end',
            'timestamp': exp.end_at.isoformat(),
            'title': exp.title,
            'id': exp.id,
            'url': url_for('view_experiment', experiment_id=exp.id)
        })

    logs = ExperimentLog.query.filter_by(experiment_id=exp.id).all()
    for l in logs:
        if l.timestamp:
            events.append({
                'type': 'log',
                'timestamp': l.timestamp.isoformat(),
                'title': 'Log entry',
                'id': l.id,
                'url': url_for('view_experiment', experiment_id=exp.id)
            })

    for d in getattr(exp, 'documents', []):
        if d.uploaded_at:
            events.append({
                'type': 'document',
                'timestamp': d.uploaded_at.isoformat(),
                'title': d.filename,
                'id': d.id,
                'url': url_for('view_experiment', experiment_id=exp.id)
            })

    grouped = {}
    for ev in events:
        try:
            ts = ev.get('timestamp')
            key = ts[:7]
        except Exception:
            key = 'unknown'
        grouped.setdefault(key, []).append(ev)

    for k in grouped:
        grouped[k].sort(key=lambda x: x.get('timestamp', ''), reverse=True)

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
    if project.database:
        log_lab_event(project.database, "created", "experiment", experiment.id, experiment.title, {"project_id": project.id})
    return redirect(url_for("view_experiment", experiment_id=experiment.id))


# ---- Experiments ----
@app.get("/experiment/<int:experiment_id>")
@app.get("/lab/<lab_slug>/experiment/<int:experiment_id>")
@app.get("/lab/<lab_slug>/project/<int:project_id>/experiment/<int:experiment_id>")
def view_experiment(experiment_id, lab_slug=None, project_id=None):
    exp = Experiment.query.get_or_404(experiment_id)
    project = exp.project
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if not project or project.database_id != lab.id:
            abort(403)
        if project_id and project.id != project_id:
            abort(404)
        set_current_lab(lab)
    else:
        if project and project.database:
            lab_key = project.database.slug or str(project.database.id)
            return redirect(url_for('view_experiment', lab_slug=lab_key, project_id=project.id, experiment_id=exp.id))

    # Linked samples: build sample tree but highlight linked ones
    linked_ids = {link.sample_id for link in exp.sample_links}
    sample_roots = [s for s in exp.project.samples if not s.parent_id]
    linked_sample_tree = [serialize_sample_tree(r) for r in sample_roots]

    # equipment choices scoped to project and lab
    try:
        lab = exp.project.database
        equipment_choices = Equipment.query.filter(
            (Equipment.project_id == exp.project_id) |
            (Equipment.database_id == (lab.id if lab else None))
        ).order_by(Equipment.name).all()
    except Exception:
        # If Equipment has no project_id column yet (older DB), fall back to all equipment
        equipment_choices = Equipment.query.order_by(Equipment.name).all()

    def _avg_measured_for_log(log):
        vals = safe_json_loads(log.values_json, [])
        measured = []
        if isinstance(vals, list):
            for item in vals:
                if isinstance(item, dict) and item.get('measured') is not None:
                    measured.append(item.get('measured'))
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    measured.append(item[1])
        if not measured:
            return None
        try:
            return sum(measured) / len(measured)
        except Exception:
            return None

    equipment_tolerance_flags = {}
    start_at = getattr(exp, 'start_at', None)
    end_at = getattr(exp, 'end_at', None) or start_at
    if start_at:
        for link in getattr(exp, 'equipment_links', []) or []:
            eq = getattr(link, 'equipment', None)
            if not eq:
                continue
            routines = CalibrationRoutine.query.filter_by(equipment_id=eq.id).all()
            routine_map = {r.name: r for r in routines}
            logs = (CalibrationLog.query
                    .filter_by(equipment_id=eq.id)
                    .filter(CalibrationLog.performed_at.isnot(None))
                    .order_by(CalibrationLog.performed_at.asc())
                    .all())

            def _is_out_of_tolerance(log):
                if not log:
                    return False, None
                avg = _avg_measured_for_log(log)
                if avg is None:
                    return False, None
                routine = routine_map.get(log.calibration_type or 'default')
                if not routine:
                    return False, None
                if routine.min_value is not None and avg < routine.min_value:
                    return True, f"{avg:.4g} < min {routine.min_value}"
                if routine.max_value is not None and avg > routine.max_value:
                    return True, f"{avg:.4g} > max {routine.max_value}"
                return False, None

            start_logs = {}
            end_logs = {}
            after_logs = {}
            for l in logs:
                cal_type = l.calibration_type or 'default'
                if l.performed_at <= start_at:
                    start_logs[cal_type] = l
                if l.performed_at <= end_at:
                    end_logs[cal_type] = l
                if l.performed_at > end_at and cal_type not in after_logs:
                    after_logs[cal_type] = l

            flagged = False
            reasons = []
            cal_types = set(routine_map.keys()) | set(start_logs.keys()) | set(end_logs.keys()) | set(after_logs.keys())
            for cal_type in sorted(cal_types):
                start_log = start_logs.get(cal_type)
                end_log = end_logs.get(cal_type)
                next_after_end = after_logs.get(cal_type)

                out, reason = _is_out_of_tolerance(start_log)
                if out and start_log:
                    flagged = True
                    reasons.append(f"{cal_type}: Start check ({start_log.performed_at.date()}): {reason}")
                out, reason = _is_out_of_tolerance(end_log)
                if out and end_log:
                    flagged = True
                    reasons.append(f"{cal_type}: End check ({end_log.performed_at.date()}): {reason}")

                out, reason = _is_out_of_tolerance(next_after_end)
                if out and next_after_end:
                    flagged = True
                    reasons.append(f"{cal_type}: After end ({next_after_end.performed_at.date()}): {reason}")

                if not next_after_end:
                    flagged = True
                    reasons.append(f"{cal_type}: No calibration after experiment end")

            for l in logs:
                if l.performed_at < start_at or l.performed_at > end_at:
                    continue
                out, reason = _is_out_of_tolerance(l)
                if out:
                    flagged = True
                    reasons.append(f"{l.calibration_type or 'default'}: During ({l.performed_at.date()}): {reason}")
                    break

            if flagged:
                equipment_tolerance_flags[eq.id] = {
                    'label': '; '.join(reasons)
                }

    equipment_calibration = {}
    start_at = getattr(exp, 'start_at', None)
    end_at = getattr(exp, 'end_at', None)
    for link in getattr(exp, 'equipment_links', []) or []:
        eq = getattr(link, 'equipment', None)
        if not eq:
            continue
        if not start_at or not end_at:
            equipment_calibration[eq.id] = {
                'status': 'unknown',
                'label': 'Set start/stop dates to check calibration.'
            }
            continue
        if not getattr(eq, 'calibration_interval_days', None):
            equipment_calibration[eq.id] = {
                'status': 'no_schedule',
                'label': 'No calibration schedule.'
            }
            continue
        last_cal = (CalibrationLog.query
                    .filter_by(equipment_id=eq.id)
                    .filter(CalibrationLog.performed_at <= end_at)
                    .order_by(CalibrationLog.performed_at.desc())
                    .first())
        if not last_cal or not last_cal.performed_at:
            equipment_calibration[eq.id] = {
                'status': 'missing',
                'label': 'No calibration on record.'
            }
            continue
        due = last_cal.performed_at + timedelta(days=eq.calibration_interval_days)
        if due < start_at:
            equipment_calibration[eq.id] = {
                'status': 'overdue_before',
                'label': f'Out of calibration before start ({due.date()}).'
            }
        elif due < end_at:
            equipment_calibration[eq.id] = {
                'status': 'overdue_during',
                'label': f'Became out of calibration on {due.date()}.'
            }
        else:
            equipment_calibration[eq.id] = {
                'status': 'ok',
                'label': f'In calibration through {end_at.date()}.'
            }

    experiment_equipment_flags = []
    for link in getattr(exp, 'equipment_links', []) or []:
        eq = getattr(link, 'equipment', None)
        if not eq:
            continue
        reasons = []
        categories = set()
        tol = equipment_tolerance_flags.get(eq.id) if equipment_tolerance_flags else None
        if tol:
            reasons.append(tol.get('label') or 'Out of tolerance during experiment period')
            categories.add('tolerance')
        cal = equipment_calibration.get(eq.id) if equipment_calibration else None
        if cal and cal.get('status') in ['overdue_before', 'overdue_during', 'missing']:
            reasons.append(cal.get('label') or 'Out of calibration period')
            categories.add('calibration')
        if reasons:
            experiment_equipment_flags.append({
                'equipment_id': eq.id,
                'equipment_name': eq.name,
                'reasons': reasons,
                'categories': sorted(categories),
                'url': url_for('view_equipment', lab_slug=(exp.project.database.slug or exp.project.database.id), equipment_id=eq.id) if exp.project and exp.project.database else url_for('view_equipment', equipment_id=eq.id),
            })

    equipment_calibration_title = {}
    for link in getattr(exp, 'equipment_links', []) or []:
        eq = getattr(link, 'equipment', None)
        if not eq:
            continue
        days_until_due = None
        next_due = None
        try:
            next_due = eq.next_due_date()
            if next_due:
                due_date = next_due.date() if hasattr(next_due, 'date') else next_due
                days_until_due = (due_date - datetime.utcnow().date()).days
        except Exception:
            next_due = None
            days_until_due = None
        routines = CalibrationRoutine.query.filter_by(equipment_id=eq.id).all()
        routine_map = {r.name: r for r in routines}
        logs = (CalibrationLog.query
                .filter_by(equipment_id=eq.id)
                .order_by(CalibrationLog.performed_at.desc(), CalibrationLog.id.desc())
                .all())
        out_of_tolerance = False
        oot_flags = []
        latest_type_checked = set()
        for l in logs:
            if not l.performed_at or not l.values_json:
                continue
            cal_type = l.calibration_type or 'default'
            if cal_type in latest_type_checked:
                continue
            latest_type_checked.add(cal_type)
            avg_measured = _avg_measured_for_log(l)
            if avg_measured is None:
                continue
            routine = routine_map.get(cal_type)
            if not routine:
                continue
            if routine.min_value is not None and avg_measured < routine.min_value:
                out_of_tolerance = True
                oot_flags.append({
                    'type': cal_type,
                    'unit': routine.unit,
                    'avg': avg_measured,
                    'bound': 'min',
                    'bound_value': routine.min_value,
                    'performed_at': l.performed_at,
                })
            if routine.max_value is not None and avg_measured > routine.max_value:
                out_of_tolerance = True
                oot_flags.append({
                    'type': cal_type,
                    'unit': routine.unit,
                    'avg': avg_measured,
                    'bound': 'max',
                    'bound_value': routine.max_value,
                    'performed_at': l.performed_at,
                })

        equipment_calibration_title[eq.id] = {
            'out_of_tolerance': out_of_tolerance,
            'oot_flags': oot_flags,
            'calibration_status': eq.calibration_status(),
            'days_until_due': days_until_due,
        }

    return render_template(
        "experiment.html",
        experiment=exp,
        linked_sample_tree=linked_sample_tree[0] if linked_sample_tree else None,
        linked_sample_ids=linked_ids,
        equipment_choices=equipment_choices,
        equipment_tolerance_flags=equipment_tolerance_flags,
        equipment_calibration=equipment_calibration,
        experiment_equipment_flags=experiment_equipment_flags,
        equipment_calibration_title=equipment_calibration_title,
        current_lab=exp.project.database,
        lab_role=db_role(current_user, project.database_id) if project and project.database_id else None,
    )


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


@app.route("/experiment/<int:experiment_id>/samples/update", methods=["POST"])
def update_experiment_samples(experiment_id):
    exp = Experiment.query.get_or_404(experiment_id)
    role = db_role(current_user, exp.project.database_id) if exp.project and exp.project.database_id else None
    if role not in ("owner", "admin", "editor"):
        abort(403)

    selected_ids = set([int(x) for x in request.form.getlist("sample_ids") if str(x).isdigit()])
    project_sample_ids = {s.id for s in exp.project.samples}
    selected_ids = selected_ids.intersection(project_sample_ids)

    existing_links = SampleExperiment.query.filter_by(experiment_id=exp.id).all()
    existing_ids = {l.sample_id for l in existing_links}

    for link in existing_links:
        if link.sample_id not in selected_ids:
            db.session.delete(link)

    for sid in selected_ids:
        if sid not in existing_ids:
            db.session.add(SampleExperiment(sample_id=sid, experiment_id=exp.id, role="other"))

    db.session.commit()
    flash("Linked samples updated.", "ok")
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
    folder = exp_upload_dir(experiment.project_id, experiment.id)
    stored_path, _ = save_uploaded_file(file, folder)
    doc = Document(
        experiment=experiment,
        filename=file.filename,  # original
        stored_path=stored_path,
        mimetype=file.mimetype,
        uploaded_by_user_id=_uid(),
    )
    db.session.add(doc)
    db.session.commit()
    try:
        log_lab_event(experiment.project.database, "document_uploaded", "experiment", experiment.id, file.filename, {"doc_id": doc.id})
    except Exception:
        pass
    try:
        user_label = current_user.name or current_user.email if getattr(current_user, "is_authenticated", False) else None
        db.session.add(ExperimentLog(experiment_id=experiment.id, user=user_label, notes=f"Uploaded document: {file.filename}"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    flash("File uploaded.", "ok")
    return redirect(url_for("view_experiment", experiment_id=experiment.id))


@app.route("/download/<int:doc_id>")
def download(doc_id):
    d = Document.query.get_or_404(doc_id)
    return send_stored_file(d.stored_path, d.filename)


@app.post("/experiment/doc/<int:doc_id>/delete")
@login_required
def delete_experiment_doc(doc_id):
    d = Document.query.get_or_404(doc_id)
    experiment = d.experiment
    project = experiment.project if experiment else None
    if not project or not can_edit_project(project, current_user):
        abort(403)
    try:
        if d.stored_path and os.path.exists(d.stored_path):
            os.remove(d.stored_path)
    except Exception:
        pass
    filename = d.filename
    db.session.delete(d)
    db.session.commit()
    try:
        log_lab_event(project.database, "document_deleted", "experiment", experiment.id, filename, {"doc_id": doc_id})
    except Exception:
        pass
    try:
        user_label = current_user.name or current_user.email if getattr(current_user, "is_authenticated", False) else None
        db.session.add(ExperimentLog(experiment_id=experiment.id, user=user_label, notes=f"Deleted document: {filename}"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    flash("Document deleted.", "ok")
    return redirect(url_for("view_experiment", experiment_id=experiment.id))


# ---- Samples ----
@app.route("/samples")
def list_samples():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('list_samples_for_lab', lab_slug=slug, **request.args))
    flash('Select a lab to view samples.', 'error')
    return redirect(url_for('index'))


@app.route("/lab/<lab_slug>/samples")
def list_samples_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    lab_role = db_role(current_user, lab.id)
    q = request.args.get("q", "").strip()
    view = request.args.get("view", "project")  # default to project tree

    projects = Project.query.filter_by(database_id=lab.id).order_by(Project.title.asc()).all()
    project_ids = [p.id for p in projects]

    qry = Sample.query.filter(Sample.project_id.in_(project_ids)).order_by(Sample.created_at.desc())
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

    # build roots per project for the tree view
    roots_by_project = {
        p.id: [s for s in p.samples if not s.parent_id] for p in projects}

    # build grouped tree per project: Project -> Sample Class -> Stock Material -> Sample
    project_tree = {}
    for p in projects:
        roots = roots_by_project.get(p.id, [])
        class_groups = {}
        for r in roots:
            class_name = None
            if getattr(r, 'sample_class', None):
                class_name = r.sample_class.name
            elif getattr(r, 'stock_material', None) and getattr(r.stock_material, 'sample_class', None):
                class_name = r.stock_material.sample_class.name
            if not class_name:
                class_name = 'Unclassified'

            stock_obj = getattr(r, 'stock_material', None)
            if stock_obj:
                stock_label = stock_obj.name + (f" — {stock_obj.lot_number}" if stock_obj.lot_number else "")
                stock_key = f"stock:{stock_obj.id}"
                stock_entry = class_groups.setdefault(class_name, {}).setdefault(stock_key, {
                    'label': stock_label,
                    'stock_id': stock_obj.id,
                    'roots': []
                })
            else:
                stock_key = 'nostock'
                stock_entry = class_groups.setdefault(class_name, {}).setdefault(stock_key, {
                    'label': 'No Stock Material',
                    'stock_id': None,
                    'roots': []
                })
            stock_entry['roots'].append(serialize_sample_tree(r))

        # sort class groups (Unclassified last)
        sorted_class_names = sorted(class_groups.keys(), key=lambda n: (n == 'Unclassified', n.lower()))
        class_list = []
        for cname in sorted_class_names:
            stocks = class_groups[cname]
            sorted_stock_keys = sorted(stocks.keys(), key=lambda k: (stocks[k]['label'] == 'No Stock Material', stocks[k]['label'].lower()))
            class_list.append({
                'class_name': cname,
                'stocks': [stocks[k] for k in sorted_stock_keys]
            })
        project_tree[p.id] = class_list

    # options for dependent dropdowns
    experiment_opts = [
        {"id": e.id, "title": e.title, "project_id": e.project_id}
        for e in Experiment.query.filter(Experiment.project_id.in_(project_ids)).order_by(Experiment.created_at.desc()).all()
    ]
    sample_opts = [
        {"id": s.id, "name": s.name, "project_id": s.project_id, "stock_material_id": (s.stock_material_id if hasattr(s, 'stock_material_id') else None)}
        for s in Sample.query.filter(Sample.project_id.in_(project_ids)).order_by(Sample.created_at.desc()).all()
    ]
    sc_name_map = {sc.id: sc.name for sc in SampleClass.query.filter_by(database_id=lab.id).all()}
    stock_material_opts = [
        {
            "id": m.id,
            "name": m.name,
            "lot_number": m.lot_number,
            "quantity": m.quantity,
            "unit": m.unit,
            "class_attrs": safe_json_loads(getattr(m, 'class_attrs_json', None), {}),
            "sample_class_id": getattr(m, 'sample_class_id', None),
            "sample_class_name": sc_name_map.get(getattr(m, 'sample_class_id', None))
        }
        for m in StockMaterial.query.filter_by(database_id=lab.id).order_by(StockMaterial.name.asc()).all()
    ]
    sample_class_opts = []
    for sc in SampleClass.query.filter_by(database_id=lab.id).order_by(SampleClass.name.asc()).all():
        attrs = safe_json_loads(sc.attributes_json, [])
        sample_class_opts.append({
            "id": sc.id,
            "name": sc.name,
            "description": sc.description,
            "slug": sc.slug,
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
        project_tree=project_tree,
        current_lab=lab,
        lab_role=lab_role,
    )


@app.route('/api/sample-classes')
def api_sample_classes():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('api_sample_classes_for_lab', lab_slug=slug))
    return jsonify([])


@app.route('/lab/<lab_slug>/api/sample-classes')
def api_sample_classes_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    out = []
    for sc in SampleClass.query.filter_by(database_id=lab.id).order_by(SampleClass.name.asc()).all():
        try:
            attrs = safe_json_loads(sc.attributes_json, [])
        except Exception:
            attrs = []
        out.append({
            'id': sc.id,
            'name': sc.name,
            'description': sc.description,
            'slug': sc.slug,
            'attributes': attrs,
        })
    return jsonify(out)


@app.route('/stock-materials')
def list_stock_materials():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('list_stock_materials_for_lab', lab_slug=slug))
    flash('Select a lab to view stock materials.', 'error')
    return redirect(url_for('index'))


@app.route('/lab/<lab_slug>/stock-materials')
def list_stock_materials_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    lab_role = db_role(current_user, lab.id)
    sample_classes = SampleClass.query.filter_by(database_id=lab.id).order_by(SampleClass.name.asc()).all()
    materials = StockMaterial.query.filter_by(database_id=lab.id).order_by(StockMaterial.name.asc()).all()
    materials_by_class = {sc.id: [] for sc in sample_classes}
    uncategorized = []
    for m in materials:
        if m.sample_class_id:
            materials_by_class.setdefault(m.sample_class_id, []).append(m)
        else:
            uncategorized.append(m)
    sample_class_opts = []
    for sc in sample_classes:
        sample_class_opts.append({
            "id": sc.id,
            "name": sc.name,
            "description": sc.description,
            "attributes": safe_json_loads(sc.attributes_json, []),
        })
    return render_template('stock_inventory.html', sample_classes=sample_classes, materials_by_class=materials_by_class, uncategorized=uncategorized, current_lab=lab, lab_role=lab_role, sample_class_opts=sample_class_opts)


@app.route('/stock-materials/create', methods=['POST'])
def create_stock_material():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('create_stock_material_for_lab', lab_slug=slug))
    flash('Select a lab before creating stock materials.', 'error')
    return redirect(url_for('index'))


@app.route('/lab/<lab_slug>/stock-materials/create', methods=['POST'])
def create_stock_material_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Name required for stock material.', 'error')
        return redirect(url_for('list_stock_materials_for_lab', lab_slug=lab.slug))

    sample_class_id = request.form.get('sample_class_id', type=int)
    class_values = {}
    if sample_class_id:
        sc = SampleClass.query.get(sample_class_id)
        if not sc or sc.database_id != lab.id:
            flash('Invalid sample class for this lab.', 'error')
            return redirect(url_for('list_stock_materials_for_lab', lab_slug=lab.slug))
        class_attrs = safe_json_loads(sc.attributes_json, [])
        for a in class_attrs:
            aname = a.get('name')
            slug = re.sub('[^0-9a-z]+', '_', (aname or '').lower())
            key = f'sc_{slug}'
            val = (request.form.get(key) or '').strip()
            if a.get('required') and not val:
                flash(f"Missing required class attribute: {aname}", 'error')
                return redirect(url_for('list_stock_materials_for_lab', lab_slug=lab.slug))
            class_values[aname] = val

    m = StockMaterial(
        name=name,
        lot_number=(request.form.get('lot_number') or '').strip(),
        quantity=request.form.get('quantity', type=float),
        original_quantity=request.form.get('quantity', type=float),
        unit=(request.form.get('unit') or '').strip(),
        location=(request.form.get('location') or '').strip(),
        manufacturer=(request.form.get('manufacturer') or '').strip(),
        description=(request.form.get('description') or '').strip(),
        sample_class_id=sample_class_id,
        class_attrs_json=json.dumps(class_values) if class_values else None,
        database_id=lab.id,
    )
    db.session.add(m)
    db.session.commit()
    try:
        db.session.add(StockMaterialQuantityLog(
            stock_material_id=m.id,
            quantity_before=None,
            quantity_after=m.quantity,
            delta=(m.quantity if m.quantity is not None else None),
            note="Received into inventory",
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
    log_lab_event(lab, "created", "stock_material", m.id, m.name)
    flash('Stock material created.', 'ok')
    return redirect(url_for('list_stock_materials_for_lab', lab_slug=lab.slug))


@app.route('/equipment')
def list_equipment():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('list_equipment_for_lab', lab_slug=slug))
    flash('Select a lab to view equipment.', 'error')
    return redirect(url_for('index'))


@app.route('/lab/<lab_slug>/equipment')
def list_equipment_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    lab_role = db_role(current_user, lab.id)
    project_ids = [p.id for p in Project.query.filter_by(database_id=lab.id).all()]
    if project_ids:
        eqs = (Equipment.query
               .filter(db.or_(Equipment.project_id.in_(project_ids), Equipment.database_id == lab.id))
               .order_by(Equipment.name.asc())
               .all())
    else:
        eqs = Equipment.query.filter(Equipment.database_id == lab.id).order_by(Equipment.name.asc()).all()
    facilities = Facility.query.filter_by(database_id=lab.id).order_by(Facility.name.asc()).all()
    updated = False
    for fac in facilities:
        if not fac.slug:
            fac.slug = generate_facility_slug(fac.name, lab.id, exclude_id=fac.id)
            updated = True
    if updated:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
    return render_template('equipment.html', equipment=eqs, current_lab=lab, lab_role=lab_role, facilities=facilities)


@app.route('/equipment/<int:equipment_id>')
@app.route('/lab/<lab_slug>/equipment/<int:equipment_id>')
def view_equipment(equipment_id, lab_slug=None):
    eq = Equipment.query.get_or_404(equipment_id)
    eq_lab = eq.database or (eq.project.database if eq.project else None)

    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if eq_lab and eq_lab.id != lab.id:
            abort(403)
        set_current_lab(lab)
    else:
        if eq_lab:
            lab_key = eq_lab.slug or str(eq_lab.id)
            return redirect(url_for('view_equipment', lab_slug=lab_key, equipment_id=eq.id))
        lab = None

    lab = lab if lab_slug else eq_lab
    lab_role = db_role(current_user, lab.id) if lab else None
    maintenance_logs = MaintenanceLog.query.filter_by(equipment_id=eq.id).order_by(MaintenanceLog.performed_at.desc()).all()
    calibration_logs = CalibrationLog.query.filter_by(equipment_id=eq.id).order_by(CalibrationLog.performed_at.desc(), CalibrationLog.id.desc()).all()
    sorted_cal_logs = sorted(calibration_logs, key=lambda l: l.performed_at or datetime.min, reverse=True)
    calibration_routines = CalibrationRoutine.query.filter_by(equipment_id=eq.id).order_by(CalibrationRoutine.name.asc()).all()
    experiment_links = ExperimentEquipment.query.filter_by(equipment_id=eq.id).all()

    last_calibration = eq.last_calibration()
    next_due_date = eq.next_due_date()
    calibration_status = eq.calibration_status()
    days_until_due = None
    if next_due_date:
        try:
            due_date = next_due_date.date() if hasattr(next_due_date, 'date') else next_due_date
            days_until_due = (due_date - datetime.utcnow().date()).days
        except Exception:
            days_until_due = None

    routine_map = {}
    for r in calibration_routines:
        routine_map[r.name] = {
            'unit': r.unit,
            'standard': r.standard,
            'min_value': r.min_value,
            'max_value': r.max_value,
            'required_measurements': r.required_measurements,
        }

    routine_status = {}
    for l in calibration_logs:
        if not l.performed_at:
            continue
        cal_type = l.calibration_type or 'default'
        if cal_type in routine_status:
            continue
        routine_status[cal_type] = {
            'last_performed': l.performed_at,
            'next_due': l.next_due_date,
        }

    chart_points = []
    log_values_map = {}
    for l in calibration_logs:
        if not l.performed_at:
            continue
        vals = safe_json_loads(l.values_json, [])
        measured = []
        if isinstance(vals, list):
            for item in vals:
                if isinstance(item, dict) and item.get('measured') is not None:
                    measured.append(item.get('measured'))
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    measured.append(item[1])
        avg_measured = None
        if measured:
            try:
                avg_measured = sum(measured) / len(measured)
            except Exception:
                avg_measured = None
        if measured:
            log_values_map[str(l.id)] = measured
        chart_points.append({
            'performed_at': l.performed_at.isoformat(),
            'calibration_type': l.calibration_type or 'default',
            'avg_measured': avg_measured,
        })

    type_keys = set(routine_map.keys())
    for l in calibration_logs:
        type_keys.add(l.calibration_type or 'default')

    experiment_markers_by_type = {t: [] for t in type_keys}
    logs_by_type = {t: [] for t in type_keys}
    for l in calibration_logs:
        if not l.performed_at:
            continue
        cal_type = l.calibration_type or 'default'
        if cal_type not in logs_by_type:
            logs_by_type[cal_type] = []
        logs_by_type[cal_type].append(l)
    for t in logs_by_type:
        logs_by_type[t].sort(key=lambda l: l.performed_at)

    def _avg_measured(log):
        vals = safe_json_loads(log.values_json, [])
        measured = []
        if isinstance(vals, list):
            for item in vals:
                if isinstance(item, dict) and item.get('measured') is not None:
                    measured.append(item.get('measured'))
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    measured.append(item[1])
        if not measured:
            return None
        try:
            return sum(measured) / len(measured)
        except Exception:
            return None

    def _is_out_of_tolerance(log):
        if not log:
            return False
        avg = _avg_measured(log)
        if avg is None:
            return False
        routine = routine_map.get(log.calibration_type or 'default')
        if not routine:
            return False
        min_v = routine.get('min_value')
        max_v = routine.get('max_value')
        if min_v is not None and avg < min_v:
            return True
        if max_v is not None and avg > max_v:
            return True
        return False

    def _flagged_for_experiment(logs_asc, start_at, end_at):
        if not start_at or not end_at:
            return False
        if not logs_asc:
            return False
        start_log = None
        end_log = None
        next_after_end = None
        for l in logs_asc:
            if l.performed_at <= start_at:
                start_log = l
            if l.performed_at <= end_at:
                end_log = l
            if l.performed_at > end_at and next_after_end is None:
                next_after_end = l
        if _is_out_of_tolerance(start_log) or _is_out_of_tolerance(end_log) or _is_out_of_tolerance(next_after_end):
            return True
        for l in logs_asc:
            if l.performed_at < start_at or l.performed_at > end_at:
                continue
            if _is_out_of_tolerance(l):
                return True
        return False

    for link in experiment_links:
        exp = link.experiment
        if not exp:
            continue
        start_at = getattr(exp, 'start_at', None)
        end_at = getattr(exp, 'end_at', None)
        for t in type_keys:
            logs_asc = logs_by_type.get(t, [])
            flagged = _flagged_for_experiment(logs_asc, start_at, end_at)
            if getattr(exp, 'start_at', None):
                experiment_markers_by_type[t].append({
                    'type': 'start',
                    'timestamp': exp.start_at.isoformat(),
                    'title': exp.title,
                    'flagged': flagged,
                    'url': url_for('view_experiment', lab_slug=lab.slug, experiment_id=exp.id) if lab else url_for('view_experiment', experiment_id=exp.id),
                })
            if getattr(exp, 'end_at', None):
                experiment_markers_by_type[t].append({
                    'type': 'end',
                    'timestamp': exp.end_at.isoformat(),
                    'title': exp.title,
                    'flagged': flagged,
                    'url': url_for('view_experiment', lab_slug=lab.slug, experiment_id=exp.id) if lab else url_for('view_experiment', experiment_id=exp.id),
                })

    out_of_tolerance = False
    oot_label = None
    oot_flags = []
    tolerance_map = {}
    latest_type_checked = set()
    for l in calibration_logs:
        if not l.performed_at or not l.values_json:
            continue
        cal_type = l.calibration_type or 'default'
        if cal_type in latest_type_checked:
            continue
        avg_measured = _avg_measured(l)
        latest_type_checked.add(cal_type)
        if avg_measured is None:
            continue
        routine = routine_map.get(cal_type)
        if routine and avg_measured is not None:
            min_v = routine.get('min_value')
            max_v = routine.get('max_value')
            unit = routine.get('unit')
            performed_at = l.performed_at
            is_out = False
            if min_v is not None and avg_measured < min_v:
                is_out = True
                out_of_tolerance = True
                oot_flags.append({
                    'type': cal_type,
                    'unit': unit,
                    'avg': avg_measured,
                    'bound': 'min',
                    'bound_value': min_v,
                    'performed_at': performed_at,
                })
            if max_v is not None and avg_measured > max_v:
                is_out = True
                out_of_tolerance = True
                oot_flags.append({
                    'type': cal_type,
                    'unit': unit,
                    'avg': avg_measured,
                    'bound': 'max',
                    'bound_value': max_v,
                    'performed_at': performed_at,
                })
            tolerance_map[cal_type] = is_out
    if oot_flags:
        oot_label = "; ".join([
            f"{f['type']}: {f['avg']:.4g} {('<' if f['bound'] == 'min' else '>')} {f['bound']} {f['bound_value']}"
            for f in oot_flags
        ])

    lab_members = lab.members if lab else []
    facilities = Facility.query.filter_by(database_id=lab.id).order_by(Facility.name.asc()).all() if lab else []
    return render_template(
        'equipment_view.html',
        equipment=eq,
        current_lab=lab,
        lab_role=lab_role,
        lab_members=lab_members,
        maintenance_logs=maintenance_logs,
        calibration_logs=calibration_logs,
        sorted_cal_logs=sorted_cal_logs,
        calibration_routines=calibration_routines,
        routine_map=routine_map,
        chart_points=chart_points,
        log_values_map=log_values_map,
        experiment_markers_by_type=experiment_markers_by_type,
        out_of_tolerance=out_of_tolerance,
        oot_label=oot_label,
        oot_flags=oot_flags,
        tolerance_map=tolerance_map,
        routine_status=routine_status,
        experiment_links=experiment_links,
        last_calibration=last_calibration,
        next_due_date=next_due_date,
        days_until_due=days_until_due,
        calibration_status=calibration_status,
        facilities=facilities,
    )


@app.route('/facilities')
def list_facilities():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('list_facilities_for_lab', lab_slug=slug))
    flash('Select a lab to view facilities.', 'error')
    return redirect(url_for('index'))


@app.route('/lab/<lab_slug>/facilities')
def list_facilities_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    lab_role = db_role(current_user, lab.id)
    facilities = Facility.query.filter_by(database_id=lab.id).order_by(Facility.name.asc()).all()
    updated = False
    for fac in facilities:
        if not fac.slug:
            fac.slug = generate_facility_slug(fac.name, lab.id, exclude_id=fac.id)
            updated = True
    if updated:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
    lab_members = lab.members if lab else []
    return render_template('facility.html', facilities=facilities, current_lab=lab, lab_role=lab_role, lab_members=lab_members)


@app.route('/lab/<lab_slug>/facilities/<facility_slug>')
def view_facility_for_lab(lab_slug, facility_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    lab_role = db_role(current_user, lab.id)
    fac = Facility.query.filter_by(database_id=lab.id, slug=facility_slug).first()
    if not fac and facility_slug.isdigit():
        fac = Facility.query.get(int(facility_slug))
        if not fac or fac.database_id != lab.id:
            fac = None
    if not fac:
        abort(404)
    if not fac.slug:
        fac.slug = generate_facility_slug(fac.name, lab.id, exclude_id=fac.id)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
    return render_template('facility_view.html', facility=fac, current_lab=lab, lab_role=lab_role)


@app.route('/lab/<lab_slug>/facilities/<facility_slug>/update', methods=['POST'])
def update_facility_for_lab(lab_slug, facility_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin'):
        abort(403)

    fac = Facility.query.filter_by(database_id=lab.id, slug=facility_slug).first()
    if not fac and facility_slug.isdigit():
        fac = Facility.query.get(int(facility_slug))
        if not fac or fac.database_id != lab.id:
            fac = None
    if not fac:
        abort(404)

    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Facility name is required.', 'error')
        return redirect(url_for('view_facility_for_lab', lab_slug=lab.slug or lab.id, facility_slug=fac.slug or fac.id))

    manager_user_id = request.form.get('manager_user_id', type=int)
    if not manager_user_id:
        flash('Facility manager is required.', 'error')
        return redirect(url_for('view_facility_for_lab', lab_slug=lab.slug or lab.id, facility_slug=fac.slug or fac.id))
    member = DatabaseMember.query.filter_by(database_id=lab.id, user_id=manager_user_id).first()
    if not member or member.role not in ('owner', 'admin'):
        flash('Facility manager must be an owner or manager.', 'error')
        return redirect(url_for('view_facility_for_lab', lab_slug=lab.slug or lab.id, facility_slug=fac.slug or fac.id))

    state = (request.form.get('state') or '').strip()
    if not state:
        state = (request.form.get('state_text') or '').strip()

    fac.name = name
    fac.location = (request.form.get('location') or '').strip()
    fac.address_line1 = (request.form.get('address_line1') or '').strip()
    fac.address_line2 = (request.form.get('address_line2') or '').strip()
    fac.city = (request.form.get('city') or '').strip()
    fac.state = state
    fac.postal_code = (request.form.get('postal_code') or '').strip()
    fac.country = (request.form.get('country') or '').strip()
    fac.description = (request.form.get('description') or '').strip()
    fac.manager_user_id = manager_user_id

    new_slug = generate_facility_slug(name, lab.id, exclude_id=fac.id)
    fac.slug = new_slug

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash('Failed to update facility.', 'error')
        return redirect(url_for('view_facility_for_lab', lab_slug=lab.slug or lab.id, facility_slug=fac.slug or fac.id))

    flash('Facility updated.', 'ok')
    return redirect(url_for('view_facility_for_lab', lab_slug=lab.slug or lab.id, facility_slug=fac.slug or fac.id))


@app.route('/lab/<lab_slug>/facilities/<facility_slug>/delete', methods=['POST'])
def delete_facility_for_lab(lab_slug, facility_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin'):
        abort(403)

    fac = Facility.query.filter_by(database_id=lab.id, slug=facility_slug).first()
    if not fac and facility_slug.isdigit():
        fac = Facility.query.get(int(facility_slug))
        if not fac or fac.database_id != lab.id:
            fac = None
    if not fac:
        abort(404)

    try:
        db.session.delete(fac)
        db.session.commit()
        flash('Facility deleted.', 'ok')
    except Exception:
        db.session.rollback()
        flash('Failed to delete facility.', 'error')

    return redirect(url_for('list_facilities_for_lab', lab_slug=lab.slug or lab.id))


@app.route('/facilities/create', methods=['POST'])
def create_facility():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('create_facility_for_lab', lab_slug=slug))
    flash('Select a lab before creating facilities.', 'error')
    return redirect(url_for('index'))


@app.route('/lab/<lab_slug>/facilities/create', methods=['POST'])
def create_facility_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin'):
        abort(403)

    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Facility name is required.', 'error')
        return redirect(url_for('view_lab_by_slug', slug=lab.slug) if lab.slug else url_for('view_lab', db_id=lab.id))

    manager_user_id = request.form.get('manager_user_id', type=int)
    if not manager_user_id:
        flash('Facility manager is required.', 'error')
        return redirect(url_for('view_lab_by_slug', slug=lab.slug) if lab.slug else url_for('view_lab', db_id=lab.id))
    member = DatabaseMember.query.filter_by(database_id=lab.id, user_id=manager_user_id).first()
    if not member or member.role not in ('owner', 'admin'):
        flash('Facility manager must be an owner or manager.', 'error')
        return redirect(url_for('view_lab_by_slug', slug=lab.slug) if lab.slug else url_for('view_lab', db_id=lab.id))

    state = (request.form.get('state') or '').strip()
    if not state:
        state = (request.form.get('state_text') or '').strip()

    slug = generate_facility_slug(name, lab.id)

    fac = Facility(
        name=name,
        slug=slug,
        location=(request.form.get('location') or '').strip(),
        address_line1=(request.form.get('address_line1') or '').strip(),
        address_line2=(request.form.get('address_line2') or '').strip(),
        city=(request.form.get('city') or '').strip(),
        state=state,
        postal_code=(request.form.get('postal_code') or '').strip(),
        country=(request.form.get('country') or '').strip(),
        description=(request.form.get('description') or '').strip(),
        manager_user_id=manager_user_id,
        database_id=lab.id,
    )
    db.session.add(fac)
    db.session.commit()
    flash('Facility created.', 'ok')
    return redirect(url_for('list_facilities_for_lab', lab_slug=lab.slug))


@app.route('/equipment/create', methods=['POST'])
def create_equipment():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('create_equipment_for_lab', lab_slug=slug))
    flash('Select a lab before creating equipment.', 'error')
    return redirect(url_for('index'))


@app.route('/lab/<lab_slug>/equipment/create', methods=['POST'])
def create_equipment_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Equipment name is required.', 'error')
        return redirect(url_for('list_equipment_for_lab', lab_slug=lab.slug))

    purchase_date = None
    purchase_raw = (request.form.get('purchase_date') or '').strip()
    if purchase_raw:
        try:
            purchase_date = datetime.fromisoformat(purchase_raw).date()
        except Exception:
            purchase_date = None

    facility_id = request.form.get('facility_id', type=int)
    eq = Equipment(
        name=name,
        model=(request.form.get('model') or '').strip(),
        serial_number=(request.form.get('serial_number') or '').strip(),
        location=(request.form.get('location') or '').strip(),
        manufacturer=(request.form.get('manufacturer') or '').strip(),
        purchase_date=purchase_date,
        status=(request.form.get('status') or 'active').strip(),
        database_id=lab.id,
        facility_id=facility_id,
    )
    db.session.add(eq)
    db.session.commit()
    log_lab_event(lab, 'created', 'equipment', eq.id, eq.name)
    flash('Equipment created.', 'ok')
    return redirect(url_for('list_equipment_for_lab', lab_slug=lab.slug))


@app.route('/lab/<lab_slug>/equipment/<int:equipment_id>/edit', methods=['POST'])
def edit_equipment_for_lab(lab_slug, equipment_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    eq = Equipment.query.get_or_404(equipment_id)
    if eq.database_id != lab.id:
        abort(403)

    eq.name = (request.form.get('name') or '').strip() or eq.name
    eq.model = (request.form.get('model') or '').strip()
    eq.serial_number = (request.form.get('serial_number') or '').strip()
    eq.location = (request.form.get('location') or '').strip()
    eq.manufacturer = (request.form.get('manufacturer') or '').strip()
    status = (request.form.get('status') or '').strip()
    if status:
        eq.status = status
    purchase_raw = (request.form.get('purchase_date') or '').strip()
    if purchase_raw:
        try:
            eq.purchase_date = datetime.fromisoformat(purchase_raw).date()
        except Exception:
            pass

    facility_id = request.form.get('facility_id', type=int)
    eq.facility_id = facility_id
    db.session.commit()
    flash('Equipment updated.', 'ok')
    return redirect(url_for('list_equipment_for_lab', lab_slug=lab.slug))


@app.route('/lab/<lab_slug>/equipment/<int:equipment_id>/calibration/routine', methods=['POST'])
def set_equipment_calibration_routine(lab_slug, equipment_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    eq = Equipment.query.get_or_404(equipment_id)
    if eq.database_id != lab.id:
        abort(403)

    interval_raw = (request.form.get('calibration_interval_days') or '').strip()
    if interval_raw == '':
        eq.calibration_interval_days = None
    else:
        try:
            interval_val = int(interval_raw)
            if interval_val <= 0:
                raise ValueError('Interval must be positive')
            eq.calibration_interval_days = interval_val
        except Exception:
            flash('Calibration interval must be a positive whole number (days).', 'error')
            return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    db.session.commit()
    flash('Calibration routine updated.', 'ok')
    return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))


@app.route('/lab/<lab_slug>/equipment/<int:equipment_id>/calibration/type/add', methods=['POST'])
def add_equipment_calibration_type(lab_slug, equipment_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    eq = Equipment.query.get_or_404(equipment_id)
    if eq.database_id != lab.id:
        abort(403)

    name = (request.form.get('name') or '').strip()
    unit = (request.form.get('unit') or '').strip()
    standard = (request.form.get('standard') or '').strip()
    min_raw = (request.form.get('min_value') or '').strip()
    max_raw = (request.form.get('max_value') or '').strip()
    req_raw = (request.form.get('required_measurements') or '').strip()

    if not name:
        flash('Calibration type is required.', 'error')
        return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    min_val = None
    max_val = None
    req_val = None
    try:
        if min_raw != '':
            min_val = float(min_raw)
        if max_raw != '':
            max_val = float(max_raw)
        if req_raw != '':
            req_val = int(req_raw)
            if req_val <= 0:
                raise ValueError('required_measurements must be positive')
    except Exception:
        flash('Invalid numeric values for min/max/required measurements.', 'error')
        return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    routine = CalibrationRoutine(
        equipment_id=eq.id,
        name=name,
        measurement='',
        unit=unit or None,
        standard=standard or None,
        min_value=min_val,
        max_value=max_val,
        required_measurements=req_val,
    )
    db.session.add(routine)
    db.session.commit()
    flash('Calibration type added.', 'ok')
    return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))


@app.route('/lab/<lab_slug>/equipment/<int:equipment_id>/calibration/type/<int:routine_id>/delete', methods=['POST'])
def delete_equipment_calibration_type(lab_slug, equipment_id, routine_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    eq = Equipment.query.get_or_404(equipment_id)
    if eq.database_id != lab.id:
        abort(403)

    routine = CalibrationRoutine.query.get_or_404(routine_id)
    if routine.equipment_id != eq.id:
        abort(403)

    db.session.delete(routine)
    db.session.commit()
    flash('Calibration type deleted.', 'ok')
    return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))


@app.route('/lab/<lab_slug>/equipment/<int:equipment_id>/calibration/log', methods=['POST'])
def add_calibration_log(lab_slug, equipment_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    eq = Equipment.query.get_or_404(equipment_id)
    if eq.database_id != lab.id:
        abort(403)

    calibration_type = (request.form.get('calibration_type') or '').strip()
    performed_by = (request.form.get('performed_by') or '').strip()
    performed_raw = (request.form.get('performed_at') or '').strip()
    temperature_raw = (request.form.get('temperature') or '').strip()
    measurements_raw = (request.form.get('measurements') or '').strip()
    measurements_list = request.form.getlist('measurements')

    performed_at = datetime.utcnow()
    if performed_raw:
        try:
            performed_at = datetime.fromisoformat(performed_raw)
        except Exception:
            flash('Invalid calibration date/time.', 'error')
            return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    temperature = None
    if temperature_raw:
        try:
            temperature = float(temperature_raw)
        except Exception:
            flash('Temperature must be a number.', 'error')
            return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    measurements = []
    if measurements_list:
        for val in measurements_list:
            v = (val or '').strip()
            if not v:
                continue
            try:
                measurements.append(float(v))
            except Exception:
                flash('Measurements must be numbers.', 'error')
                return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))
    elif measurements_raw:
        raw_parts = []
        for line in measurements_raw.splitlines():
            raw_parts.extend([p for p in line.split(',')])
        for p in raw_parts:
            val = p.strip()
            if not val:
                continue
            try:
                measurements.append(float(val))
            except Exception:
                flash('Measurements must be numbers (comma or newline separated).', 'error')
                return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    routine = None
    if calibration_type:
        routine = CalibrationRoutine.query.filter_by(equipment_id=eq.id, name=calibration_type).first()

    if routine and routine.required_measurements:
        if len(measurements) < routine.required_measurements:
            flash(f'At least {routine.required_measurements} measurements are required for this calibration type.', 'error')
            return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    values_json = None
    if measurements:
        values_json = json.dumps([{'measured': v} for v in measurements])

    next_due_date = None
    if eq.calibration_interval_days:
        try:
            next_due_date = performed_at + timedelta(days=eq.calibration_interval_days)
        except Exception:
            next_due_date = None

    log = CalibrationLog(
        equipment_id=eq.id,
        performed_by=performed_by or None,
        performed_at=performed_at,
        temperature=temperature,
        values_json=values_json,
        calibration_type=calibration_type or None,
        next_due_date=next_due_date,
    )
    db.session.add(log)
    db.session.commit()
    flash('Calibration logged.', 'ok')
    return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))


@app.route('/lab/<lab_slug>/calibration/log/<int:log_id>/edit', methods=['POST'])
def edit_calibration_log(lab_slug, log_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    log = CalibrationLog.query.get_or_404(log_id)
    eq = Equipment.query.get_or_404(log.equipment_id)
    if eq.database_id != lab.id:
        abort(403)

    calibration_type = (request.form.get('calibration_type') or '').strip()
    performed_by = (request.form.get('performed_by') or '').strip()
    performed_raw = (request.form.get('performed_at') or '').strip()
    measurements_raw = (request.form.get('measurements') or '').strip()
    measurements_list = request.form.getlist('measurements')

    performed_at = log.performed_at or datetime.utcnow()
    if performed_raw:
        try:
            performed_at = datetime.fromisoformat(performed_raw)
        except Exception:
            flash('Invalid calibration date/time.', 'error')
            return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    measurements = []
    if measurements_list:
        for val in measurements_list:
            v = (val or '').strip()
            if not v:
                continue
            try:
                measurements.append(float(v))
            except Exception:
                flash('Measurements must be numbers.', 'error')
                return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))
    elif measurements_raw:
        raw_parts = []
        for line in measurements_raw.splitlines():
            raw_parts.extend([p for p in line.split(',')])
        for p in raw_parts:
            val = p.strip()
            if not val:
                continue
            try:
                measurements.append(float(val))
            except Exception:
                flash('Measurements must be numbers (comma or newline separated).', 'error')
                return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    routine = None
    if calibration_type:
        routine = CalibrationRoutine.query.filter_by(equipment_id=eq.id, name=calibration_type).first()

    if routine and routine.required_measurements:
        if len(measurements) < routine.required_measurements:
            flash(f'At least {routine.required_measurements} measurements are required for this calibration type.', 'error')
            return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))

    values_json = None
    if measurements:
        values_json = json.dumps([{'measured': v} for v in measurements])

    next_due_date = None
    if eq.calibration_interval_days:
        try:
            next_due_date = performed_at + timedelta(days=eq.calibration_interval_days)
        except Exception:
            next_due_date = None

    log.calibration_type = calibration_type or None
    log.performed_by = performed_by or None
    log.performed_at = performed_at
    log.values_json = values_json
    log.next_due_date = next_due_date
    db.session.commit()
    flash('Calibration log updated.', 'ok')
    return redirect(url_for('view_equipment', lab_slug=lab.slug, equipment_id=eq.id))


@app.route('/sample-classes/create', methods=['POST'])
def create_sample_class():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('create_sample_class_for_lab', lab_slug=slug))
    flash('Select a lab before creating sample classes.', 'error')
    return redirect(url_for('index'))


@app.route('/lab/<lab_slug>/sample-classes/create', methods=['POST'])
def create_sample_class_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    name = (request.form.get('name') or '').strip()
    description = (request.form.get('description') or '').strip()
    slug = (request.form.get('slug') or '').strip()
    attrs_raw = (request.form.get('attributes') or '').strip()
    if not name:
        flash('Sample class name is required.', 'error')
        return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug))

    if not slug:
        slug = re.sub('[^0-9a-z]+', '_', name.lower())

    # attrs_raw is expected to be JSON array of attribute objects
    try:
        attrs = json.loads(attrs_raw) if attrs_raw else []
        if not isinstance(attrs, list):
            raise ValueError('attributes must be a JSON array')
    except Exception as e:
        flash('Invalid attributes JSON: ' + str(e), 'error')
        return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug))

    sc = SampleClass(name=name, slug=slug, description=description, attributes_json=json.dumps(attrs), database_id=lab.id)
    db.session.add(sc)
    db.session.commit()
    flash('Sample class created.', 'ok')
    return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug))


@app.route('/lab/<lab_slug>/sample-classes/<int:class_id>/update', methods=['POST'])
def update_sample_class_for_lab(lab_slug, class_id):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    role = db_role(current_user, lab.id)
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    sc = SampleClass.query.get_or_404(class_id)
    if sc.database_id != lab.id:
        abort(403)

    name = (request.form.get('name') or '').strip()
    description = (request.form.get('description') or '').strip()
    slug = (request.form.get('slug') or '').strip()
    if not name:
        flash('Sample class name is required.', 'error')
        return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug))

    if not slug:
        slug = re.sub('[^0-9a-z]+', '_', name.lower())
    if re.search(r'[^0-9a-z_]', slug):
        flash('Slug must use lowercase letters, numbers, or underscores.', 'error')
        return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug))

    existing = SampleClass.query.filter(
        SampleClass.database_id == lab.id,
        SampleClass.slug == slug,
        SampleClass.id != sc.id
    ).first()
    if existing:
        flash('That slug is already used by another sample class.', 'error')
        return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug))

    attrs_raw = (request.form.get('attributes') or '').strip()
    try:
        attrs = json.loads(attrs_raw) if attrs_raw else []
        if not isinstance(attrs, list):
            raise ValueError('attributes must be a JSON array')
    except Exception as e:
        flash('Invalid attributes JSON: ' + str(e), 'error')
        return redirect(url_for('list_stock_materials_for_lab', lab_slug=lab.slug))

    sc.attributes_json = json.dumps(attrs)
    sc.name = name
    sc.description = description
    sc.slug = slug
    db.session.commit()
    flash('Sample class attributes updated.', 'ok')
    return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug))


@app.route("/samples/create", methods=["POST"])
def create_sample():
    slug = session.get('current_lab_slug')
    if slug:
        return redirect(url_for('create_sample_for_lab', lab_slug=slug))
    flash('Select a lab before creating samples.', 'error')
    return redirect(url_for('index'))


@app.route("/lab/<lab_slug>/samples/create", methods=["POST"])
def create_sample_for_lab(lab_slug):
    lab = get_lab_or_404(lab_slug)
    set_current_lab(lab)
    parent_id = request.form.get("parent_id", type=int)
    project_id = request.form.get("project_id", type=int)
    name = (request.form.get("name") or "").strip()

    # NEW: optional experiment link on creation
    experiment_id = request.form.get("experiment_id", type=int)
    link_role = (request.form.get("role") or "other").strip().lower()
    link_notes = (request.form.get("notes") or "").strip()

    parent = Sample.query.get(parent_id) if parent_id else None
    root = get_sample_root(parent) if parent else None
    if parent:
        project_id = parent.project_id

    if not project_id or not name:
        flash("Project (or parent) and sample name are required.", "error")
        return redirect(url_for("list_samples_for_lab", lab_slug=lab.slug))

    project = Project.query.get(project_id)
    if not project or project.database_id != lab.id:
        flash("Selected project does not belong to this lab.", "error")
        return redirect(url_for("list_samples_for_lab", lab_slug=lab.slug))

    # Determine stock material and sample class (inherited from stock material)
    from_stock = (request.form.get('from_stock') or '').strip().lower() == 'yes'
    stock_material_id = request.form.get('stock_material_id', type=int)
    extra_stock_ids = [int(x) for x in request.form.getlist('stock_material_id_extra') if str(x).strip().isdigit()]
    new_qty = request.form.get('stock_new_quantity', type=float)
    sample_qty = request.form.get('sample_quantity', type=float)
    if not from_stock:
        extra_stock_ids = []
    if parent:
        root = get_sample_root(parent)
        stock_material_id = getattr(root, 'stock_material_id', None)
        extra_stock_ids = []
        if not stock_material_id:
            flash('Parent sample has no stock material to inherit.', 'error')
            return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))
    else:
        if from_stock and not stock_material_id:
            if not extra_stock_ids:
                flash('Stock material is required when origin is stock.', 'error')
                return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))
            stock_material_id = extra_stock_ids[0]

    mat = StockMaterial.query.get(stock_material_id) if stock_material_id else None
    mats = []
    if mat:
        mats.append(mat)
    for mid in extra_stock_ids:
        if mat and mid == mat.id:
            continue
        mobj = StockMaterial.query.get(mid)
        if mobj:
            mats.append(mobj)

    for mobj in mats:
        if mobj.database_id != lab.id:
            flash('Invalid stock material for this lab.', 'error')
            return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))

    for mobj in mats:
        if mobj and mobj.created_at:
            if datetime.utcnow() < mobj.created_at:
                flash('Cannot create a sample before the stock material was received into inventory.', 'error')
                return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))

    if mat and from_stock and not parent:
        if new_qty is None:
            flash('New stock quantity is required when splitting from stock material.', 'error')
            return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))
        if sample_qty is None:
            flash('Sample quantity is required when splitting from stock material.', 'error')
            return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))

    extra_qty_raw = request.form.getlist('stock_use_qty_extra')
    extra_qty = []
    for v in extra_qty_raw:
        try:
            extra_qty.append(float(v))
        except Exception:
            extra_qty.append(None)
    if extra_stock_ids and from_stock and not parent:
        if len(extra_qty) < len(extra_stock_ids) or any(q is None for q in extra_qty[:len(extra_stock_ids)]):
            flash('Quantity used is required for each additional stock material.', 'error')
            return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))

    sample_class_id = root.sample_class_id if root and getattr(root, 'sample_class_id', None) else None
    if not sample_class_id:
        if len(mats) == 1 and mat:
            sample_class_id = mat.sample_class_id
        elif len(mats) > 1:
            class_ids = {getattr(mobj, 'sample_class_id', None) for mobj in mats}
            class_ids = {c for c in class_ids if c}
            if len(class_ids) == 1:
                sample_class_id = class_ids.pop()
    if request.form.get('sample_class_id'):
        sample_class_id = request.form.get('sample_class_id', type=int)

    # Handle sample class attributes (lab-level classes)
    class_attrs = []
    class_values = {}
    inherit_from_parent = bool(root and getattr(root, 'class_attrs_json', None))
    inherit_from_stock = bool(mat and from_stock and not parent and getattr(mat, 'class_attrs_json', None) and len(mats) == 1)
    if inherit_from_parent:
        class_values = safe_json_loads(getattr(root, 'class_attrs_json', None), {})
    elif inherit_from_stock:
        class_values = safe_json_loads(getattr(mat, 'class_attrs_json', None), {})
    elif sample_class_id:
        sc = SampleClass.query.get(sample_class_id)
        if sc and sc.database_id == lab.id:
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
                    return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))
                class_values[aname] = val
        else:
            flash('Invalid sample class for this lab.', 'error')
            return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get('view', 'project')))

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
        return redirect(url_for("list_samples_for_lab", lab_slug=lab.slug, view=request.args.get("view", "project")))

    # create the sample
    sample = Sample(project_id=project_id, parent_id=(
        parent.id if parent else None), name=name, creator_id=_uid())
    # handle stock material: only allow setting on root samples
    if parent:
        root = get_sample_root(parent)
        sample.stock_material_id = getattr(root, 'stock_material_id', None)
    else:
        sample.stock_material_id = stock_material_id

    db.session.add(sample)
    db.session.commit()

    log_lab_event(lab, "created", "sample", sample.id, sample.name, {"project_id": project_id})

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

    # update stock quantity and log if split from stock
    if mat and from_stock and not parent:
        before_qty = mat.quantity
        mat.quantity = new_qty
        delta = (new_qty - before_qty) if (before_qty is not None and new_qty is not None) else None
        proj_name = None
        try:
            proj_name = sample.project.title
        except Exception:
            proj_name = None
        unit = mat.unit or ''
        loss = None
        if before_qty is not None and new_qty is not None and sample_qty is not None:
            loss = before_qty - (new_qty + sample_qty)
        parts = [f"{proj_name} · {sample.name}" if proj_name else f"{sample.name}"]
        if sample_qty is not None:
            parts.append(f"Sample qty: {sample_qty}{(' ' + unit) if unit else ''}")
        if loss is not None:
            parts.append(f"Losses: {loss}{(' ' + unit) if unit else ''}")
        note = " · ".join(parts)
        db.session.add(StockMaterialQuantityLog(
            stock_material_id=mat.id,
            sample_id=sample.id,
            quantity_before=before_qty,
            quantity_after=new_qty,
            delta=delta,
            note=note
        ))
        db.session.add(SampleStockMaterial(sample_id=sample.id, stock_material_id=mat.id, quantity_used=sample_qty))
        db.session.commit()

    if extra_stock_ids and from_stock and not parent:
        for idx, mid in enumerate(extra_stock_ids):
            mobj = StockMaterial.query.get(mid)
            if not mobj:
                continue
            qty_used = extra_qty[idx] if idx < len(extra_qty) else None
            before_qty = mobj.quantity
            new_qty_calc = None
            if before_qty is not None and qty_used is not None:
                new_qty_calc = before_qty - qty_used
                if new_qty_calc < 0:
                    flash(f'Quantity used exceeds available stock for {mobj.name}.', 'error')
                    return redirect(url_for('list_samples_for_lab', lab_slug=lab.slug, view=request.args.get("view", "project")))
                mobj.quantity = new_qty_calc
            delta = (new_qty_calc - before_qty) if (before_qty is not None and new_qty_calc is not None) else None
            unit = mobj.unit or ''
            note = f"Sample mix qty: {qty_used}{(' ' + unit) if unit else ''}" if qty_used is not None else None
            db.session.add(StockMaterialQuantityLog(
                stock_material_id=mobj.id,
                sample_id=sample.id,
                quantity_before=before_qty,
                quantity_after=new_qty_calc,
                delta=delta,
                note=note
            ))
            db.session.add(SampleStockMaterial(sample_id=sample.id, stock_material_id=mobj.id, quantity_used=qty_used))
        db.session.commit()

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

    root = get_sample_root(parent)
    for a in attrs:
        key = f"attr_{a.id}"
        if getattr(a, 'inherited', False):
            pav = SampleAttributeValue.query.filter_by(sample_id=root.id, attribute_id=a.id).first()
            val = pav.value if pav else ""
        else:
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
@app.route("/lab/<lab_slug>/sample/<int:sample_id>")
@app.route("/lab/<lab_slug>/project/<int:project_id>/sample/<int:sample_id>")
def view_sample(sample_id, lab_slug=None, project_id=None):
    sample = Sample.query.get_or_404(sample_id)
    project = sample.project
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if not project or project.database_id != lab.id:
            abort(403)
        if project_id and project.id != project_id:
            abort(404)
        set_current_lab(lab)
    else:
        if project and project.database:
            lab_key = project.database.slug or str(project.database.id)
            return redirect(url_for('view_sample', lab_slug=lab_key, project_id=project.id, sample_id=sample.id))
    exp_choices = Experiment.query.filter_by(
        project_id=sample.project_id).order_by(Experiment.created_at.desc()).all()

    lab_role = db_role(current_user, project.database_id) if project and project.database_id else None

    # lineage & tree (if you already added them) ...
    lineage = get_sample_lineage(sample)

    # Build defs for display + editing
    attrs = get_project_attrs(sample.project_id)
    val_by_attr = {v.attribute_id: v for v in sample.attribute_values}
    root = get_sample_root(sample)
    root_vals_by_attr = {v.attribute_id: v for v in getattr(root, 'attribute_values', [])} if root else {}

    needs_update = 0
    attr_defs = []
    for a in attrs:
        if getattr(a, 'inherited', False) and sample.parent_id:
            v = root_vals_by_attr.get(a.id)
        else:
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
            "inherited": bool(getattr(a, 'inherited', False)),
            "choices": safe_json_loads(a.choices_json, []),
            "value": value,
            "is_placeholder": placeholder,
            "unit": a.unit or ""
        })

    # Sample class attributes (display/edit)
    class_attr_defs = []
    class_attrs_values = safe_json_loads(getattr(sample, 'class_attrs_json', None), {})
    class_attrs_inherited = False
    if sample.parent_id:
        class_attrs_inherited = True
        if root and getattr(root, 'class_attrs_json', None):
            class_attrs_values = safe_json_loads(getattr(root, 'class_attrs_json', None), {})
    elif sample.stock_material and getattr(sample.stock_material, 'class_attrs_json', None):
        class_attrs_inherited = True
        class_attrs_values = safe_json_loads(getattr(sample.stock_material, 'class_attrs_json', None), {})

    sc = getattr(sample, 'sample_class', None)
    psc = getattr(sample, 'project_class', None)
    base_class = sc or getattr(psc, 'sample_class', None)
    base_attrs_json = getattr(base_class, 'attributes_json', None)
    if base_attrs_json:
        base_attrs = safe_json_loads(base_attrs_json, [])
        if psc and getattr(psc, 'attributes_override_json', None):
            override = safe_json_loads(psc.attributes_override_json, [])
            merged = []
            names = {a.get('name'): a for a in override if isinstance(a, dict)}
            for a in base_attrs:
                if isinstance(a, dict) and a.get('name') in names:
                    merged.append(names.pop(a.get('name')))
                else:
                    merged.append(a)
            merged.extend(names.values())
        else:
            merged = base_attrs

        for a in merged:
            if not isinstance(a, dict):
                continue
            aname = a.get('name')
            if not aname:
                continue
            slug = re.sub('[^0-9a-z]+', '_', (aname or '').lower())
            class_attr_defs.append({
                "name": aname,
                "field_type": a.get('field_type') or 'text',
                "required": bool(a.get('required')),
                "choices": a.get('choices') or [],
                "unit": a.get('unit') or "",
                "value": class_attrs_values.get(aname, ""),
                "form_key": f"sc_{slug}",
            })

    def _avg_measured_for_log(log):
        vals = safe_json_loads(log.values_json, [])
        measured = []
        if isinstance(vals, list):
            for item in vals:
                if isinstance(item, dict) and item.get('measured') is not None:
                    measured.append(item.get('measured'))
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    measured.append(item[1])
        if not measured:
            return None
        try:
            return sum(measured) / len(measured)
        except Exception:
            return None

    def _experiment_equipment_flags(exp):
        start_at = getattr(exp, 'start_at', None)
        end_at = getattr(exp, 'end_at', None) or start_at
        if not start_at:
            return []
        flags = []
        for link in getattr(exp, 'equipment_links', []) or []:
            eq = getattr(link, 'equipment', None)
            if not eq:
                continue
            routines = CalibrationRoutine.query.filter_by(equipment_id=eq.id).all()
            routine_map = {r.name: r for r in routines}
            logs = (CalibrationLog.query
                    .filter_by(equipment_id=eq.id)
                    .filter(CalibrationLog.performed_at.isnot(None))
                    .order_by(CalibrationLog.performed_at.asc())
                    .all())

            def _is_out_of_tolerance(log):
                if not log:
                    return False, None
                avg = _avg_measured_for_log(log)
                if avg is None:
                    return False, None
                routine = routine_map.get(log.calibration_type or 'default')
                if not routine:
                    return False, None
                if routine.min_value is not None and avg < routine.min_value:
                    return True, f"{avg:.4g} < min {routine.min_value}"
                if routine.max_value is not None and avg > routine.max_value:
                    return True, f"{avg:.4g} > max {routine.max_value}"
                return False, None

            start_logs = {}
            end_logs = {}
            after_logs = {}
            for l in logs:
                cal_type = l.calibration_type or 'default'
                if l.performed_at <= start_at:
                    start_logs[cal_type] = l
                if l.performed_at <= end_at:
                    end_logs[cal_type] = l
                if l.performed_at > end_at and cal_type not in after_logs:
                    after_logs[cal_type] = l

            tol_reasons = []
            cal_types = set(routine_map.keys()) | set(start_logs.keys()) | set(end_logs.keys()) | set(after_logs.keys())
            for cal_type in sorted(cal_types):
                start_log = start_logs.get(cal_type)
                end_log = end_logs.get(cal_type)
                next_after_end = after_logs.get(cal_type)

                out, reason = _is_out_of_tolerance(start_log)
                if out and start_log:
                    tol_reasons.append(f"{cal_type}: Start check ({start_log.performed_at.date()}): {reason}")
                out, reason = _is_out_of_tolerance(end_log)
                if out and end_log:
                    tol_reasons.append(f"{cal_type}: End check ({end_log.performed_at.date()}): {reason}")
                out, reason = _is_out_of_tolerance(next_after_end)
                if out and next_after_end:
                    tol_reasons.append(f"{cal_type}: After end ({next_after_end.performed_at.date()}): {reason}")
                if not next_after_end:
                    tol_reasons.append(f"{cal_type}: No calibration after experiment end")

            if not tol_reasons:
                for l in logs:
                    if l.performed_at < start_at or l.performed_at > end_at:
                        continue
                    out, reason = _is_out_of_tolerance(l)
                    if out:
                        tol_reasons.append(f"{l.calibration_type or 'default'}: During ({l.performed_at.date()}): {reason}")
                        break

            cal_reason = None
            if getattr(eq, 'calibration_interval_days', None):
                last_cal = (CalibrationLog.query
                            .filter_by(equipment_id=eq.id)
                            .filter(CalibrationLog.performed_at <= end_at)
                            .order_by(CalibrationLog.performed_at.desc())
                            .first())
                if not last_cal or not last_cal.performed_at:
                    cal_reason = 'No calibration on record'
                else:
                    due = last_cal.performed_at + timedelta(days=eq.calibration_interval_days)
                    if due < start_at:
                        cal_reason = f'Out of calibration before start ({due.date()})'
                    elif due < end_at:
                        cal_reason = f'Out of calibration during experiment ({due.date()})'

            reasons = []
            categories = []
            if tol_reasons:
                reasons.extend(tol_reasons)
                categories.append('tolerance')
            if cal_reason:
                reasons.append(cal_reason)
                categories.append('calibration')
            if reasons:
                flags.append({
                    'equipment_id': eq.id,
                    'equipment_name': eq.name,
                    'reasons': reasons,
                    'categories': categories,
                })
        return flags

    # collect own + ancestor experiment links (inheritance)
    combined_experiment_links = []
    seen_exp_ids = set()
    for l in getattr(sample, 'experiment_links', []) or []:
        combined_experiment_links.append({
            'link': l,
            'inherited': False,
            'source_sample': sample,
        })
        seen_exp_ids.add(l.experiment_id)
    ancestor = sample.parent
    while ancestor:
        for l in getattr(ancestor, 'experiment_links', []) or []:
            if l.experiment_id in seen_exp_ids:
                continue
            combined_experiment_links.append({
                'link': l,
                'inherited': True,
                'source_sample': ancestor,
            })
            seen_exp_ids.add(l.experiment_id)
        ancestor = ancestor.parent

    flagged_experiments = set()
    for item in combined_experiment_links:
        exp = getattr(item.get('link'), 'experiment', None)
        if not exp:
            continue
        flags = _experiment_equipment_flags(exp)
        if flags:
            flagged_experiments.add(exp.id)

    return render_template(
        "sample.html",
        sample=sample,
        exp_choices=exp_choices,
        lineage=lineage,
        family_tree=serialize_sample_tree(get_sample_root(sample), sample.id),
        attr_defs=attr_defs,
        class_attr_defs=class_attr_defs,
        class_attrs_inherited=class_attrs_inherited,
        needs_update=needs_update,
        stock_material_attrs=safe_json_loads(sample.stock_material.class_attrs_json, {}) if sample.stock_material and getattr(sample.stock_material, 'class_attrs_json', None) else {},
        sample_stock_materials=SampleStockMaterial.query.filter_by(sample_id=sample.id).all(),
        stock_materials=StockMaterial.query.filter_by(database_id=sample.project.database_id).order_by(StockMaterial.name.asc()).all(),
        current_lab=sample.project.database,
        lab_role=lab_role,
        sample_logs=SampleLog.query.filter_by(sample_id=sample.id).order_by(SampleLog.created_at.desc()).all(),
        flagged_experiments=flagged_experiments,
        combined_experiment_links=combined_experiment_links,
    )


@app.route('/sample/<int:sample_id>/log/add', methods=['POST'])
@app.route('/lab/<lab_slug>/sample/<int:sample_id>/log/add', methods=['POST'])
@app.route('/lab/<lab_slug>/project/<int:project_id>/sample/<int:sample_id>/log/add', methods=['POST'])
@login_required
def add_sample_log(sample_id, lab_slug=None, project_id=None):
    sample = Sample.query.get_or_404(sample_id)
    project = sample.project
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if not project or project.database_id != lab.id:
            abort(403)
        if project_id and project.id != project_id:
            abort(404)
        set_current_lab(lab)
    else:
        if project and project.database:
            lab_key = project.database.slug or str(project.database.id)
            return redirect(url_for('add_sample_log', lab_slug=lab_key, project_id=project.id, sample_id=sample.id))

    role = db_role(current_user, project.database_id) if project and project.database_id else None
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    title = (request.form.get('title') or '').strip()
    notes = (request.form.get('notes') or '').strip()
    if not title:
        flash('Log title is required.', 'error')
        return redirect(url_for('view_sample', lab_slug=lab_slug, project_id=project.id, sample_id=sample.id) if lab_slug else url_for('view_sample', sample_id=sample.id))

    entry = SampleLog(sample_id=sample.id, user_id=_uid(), title=title, notes=notes)
    db.session.add(entry)
    db.session.commit()
    flash('Log entry added.', 'ok')
    return redirect(url_for('view_sample', lab_slug=lab_slug, project_id=project.id, sample_id=sample.id) if lab_slug else url_for('view_sample', sample_id=sample.id))


@app.route('/sample/<int:sample_id>/timeline')
@app.route('/lab/<lab_slug>/sample/<int:sample_id>/timeline')
def sample_timeline(sample_id, lab_slug=None):
    sample = Sample.query.get_or_404(sample_id)
    project = sample.project
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if not project or project.database_id != lab.id:
            abort(403)
        set_current_lab(lab)
    else:
        if project and project.database:
            lab_key = project.database.slug or str(project.database.id)
            return redirect(url_for('sample_timeline', lab_slug=lab_key, sample_id=sample.id))

    root = get_sample_root(sample)
    tree_samples = [root] + list(get_descendants(root)) if root else [sample]
    tree_ids = [s.id for s in tree_samples]

    def _sample_url(s):
        return url_for('view_sample', lab_slug=lab.slug, project_id=project.id, sample_id=s.id) if lab_slug else url_for('view_sample', sample_id=s.id)

    def _exp_url(exp):
        return url_for('view_experiment', lab_slug=lab.slug, project_id=exp.project_id, experiment_id=exp.id) if lab_slug else url_for('view_experiment', experiment_id=exp.id)

    events = []
    linked_experiments = {}
    for s in tree_samples:
        if s.created_at:
            events.append({
                'type': 'sample_created',
                'timestamp': s.created_at.isoformat(),
                'title': s.name,
                'id': s.id,
                'url': _sample_url(s)
            })

        for d in getattr(s, 'documents', []):
            if d.uploaded_at:
                events.append({
                    'type': 'document',
                    'timestamp': d.uploaded_at.isoformat(),
                    'title': f"{s.name}: {d.filename}",
                    'id': d.id,
                    'url': _sample_url(s)
                })

        for m in getattr(s, 'measurements', []):
            if m.measured_at:
                events.append({
                    'type': 'measurement',
                    'timestamp': m.measured_at.isoformat(),
                    'title': f"{s.name}: Measurement {m.id}",
                    'id': m.id,
                    'url': _sample_url(s)
                })

        for l in getattr(s, 'experiment_links', []) or []:
            exp = getattr(l, 'experiment', None)
            if not exp or exp.id in linked_experiments:
                continue
            linked_experiments[exp.id] = {
                'exp': exp,
                'sample_name': s.name,
            }

    for log in SampleLog.query.filter(SampleLog.sample_id.in_(tree_ids)).all():
        if log.created_at:
            events.append({
                'type': 'log',
                'timestamp': log.created_at.isoformat(),
                'title': log.title,
                'id': log.id,
                'url': _sample_url(next((s for s in tree_samples if s.id == log.sample_id), sample))
            })

    # experiment start/end dates relevant to this sample tree
    for data in linked_experiments.values():
        exp = data['exp']
        label_suffix = f" (linked to {data['sample_name']})" if data.get('sample_name') else ''
        if getattr(exp, 'start_at', None):
            events.append({
                'type': 'experiment_start',
                'timestamp': exp.start_at.isoformat(),
                'title': f"{exp.title}{label_suffix}",
                'id': exp.id,
                'url': _exp_url(exp)
            })
        if getattr(exp, 'end_at', None):
            events.append({
                'type': 'experiment_end',
                'timestamp': exp.end_at.isoformat(),
                'title': f"{exp.title}{label_suffix}",
                'id': exp.id,
                'url': _exp_url(exp)
            })

    grouped = {}
    for ev in events:
        ts = ev.get('timestamp') or ''
        key = ts[:7] if ts else 'unknown'
        grouped.setdefault(key, []).append(ev)

    for k in grouped:
        grouped[k].sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    return jsonify(grouped)


@app.route('/stock/<int:stock_id>')
@app.route('/lab/<lab_slug>/stock/<int:stock_id>')
def view_stock_material(stock_id, lab_slug=None):
    mat = StockMaterial.query.get_or_404(stock_id)
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if mat.database_id != lab.id:
            abort(403)
        set_current_lab(lab)
    else:
        if mat.database:
            lab_key = mat.database.slug or str(mat.database.id)
            return redirect(url_for('view_stock_material', lab_slug=lab_key, stock_id=mat.id))
    class_attrs = safe_json_loads(getattr(mat, 'class_attrs_json', None), {})
    class_attr_defs = []
    if getattr(mat, 'sample_class', None) and getattr(mat.sample_class, 'attributes_json', None):
        class_attr_defs = safe_json_loads(mat.sample_class.attributes_json, [])
        for a in class_attr_defs:
            aname = a.get('name') if isinstance(a, dict) else None
            slug = re.sub('[^0-9a-z]+', '_', (aname or '').lower())
            if isinstance(a, dict):
                a['form_key'] = f"sc_{slug}"
    lab_role = db_role(current_user, mat.database_id) if mat.database_id else None
    quantity_logs = StockMaterialQuantityLog.query.filter_by(stock_material_id=mat.id).order_by(StockMaterialQuantityLog.created_at.desc()).all()
    return render_template(
        'stock_material.html',
        mat=mat,
        current_lab=getattr(mat, 'database', None),
        class_attrs=class_attrs,
        class_attr_defs=class_attr_defs,
        lab_role=lab_role,
        quantity_logs=quantity_logs,
    )


@app.route('/stock/<int:stock_id>/timeline')
@app.route('/lab/<lab_slug>/stock/<int:stock_id>/timeline')
def stock_material_timeline(stock_id, lab_slug=None):
    mat = StockMaterial.query.get_or_404(stock_id)
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if mat.database_id != lab.id:
            abort(403)
        set_current_lab(lab)
    else:
        if mat.database:
            lab_key = mat.database.slug or str(mat.database.id)
            return redirect(url_for('stock_material_timeline', lab_slug=lab_key, stock_id=mat.id))

    events = []
    if mat.created_at:
        events.append({
            'type': 'received',
            'timestamp': mat.created_at.isoformat(),
            'title': 'Received into inventory',
            'id': mat.id,
            'url': url_for('view_stock_material', lab_slug=lab.slug, stock_id=mat.id) if lab_slug else url_for('view_stock_material', stock_id=mat.id)
        })

    samples = Sample.query.filter_by(stock_material_id=mat.id).all()
    for s in samples:
        if s.created_at:
            events.append({
                'type': 'sample_created',
                'timestamp': s.created_at.isoformat(),
                'title': s.name,
                'id': s.id,
                'url': url_for('view_sample', lab_slug=lab.slug, project_id=s.project_id, sample_id=s.id) if lab_slug else url_for('view_sample', sample_id=s.id)
            })

    grouped = {}
    for ev in events:
        ts = ev.get('timestamp') or ''
        key = ts[:7] if ts else 'unknown'
        grouped.setdefault(key, []).append(ev)

    for k in grouped:
        grouped[k].sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    return jsonify(grouped)


@app.post('/stock/<int:stock_id>/edit')
@app.post('/lab/<lab_slug>/stock/<int:stock_id>/edit')
@login_required
def edit_stock_material(stock_id, lab_slug=None):
    mat = StockMaterial.query.get_or_404(stock_id)
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if mat.database_id != lab.id:
            abort(403)
        set_current_lab(lab)

    role = db_role(current_user, mat.database_id) if mat.database_id else None
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    mat.name = (request.form.get('name') or '').strip() or mat.name
    mat.description = (request.form.get('description') or '').strip()
    mat.lot_number = (request.form.get('lot_number') or '').strip()
    mat.quantity = request.form.get('quantity', type=float)
    if role in ('owner', 'admin'):
        mat.original_quantity = request.form.get('original_quantity', type=float)
    mat.unit = (request.form.get('unit') or '').strip()
    mat.location = (request.form.get('location') or '').strip()
    mat.manufacturer = (request.form.get('manufacturer') or '').strip()

    # update class attributes if class defined
    class_values = {}
    if getattr(mat, 'sample_class', None) and getattr(mat.sample_class, 'attributes_json', None):
        attrs = safe_json_loads(mat.sample_class.attributes_json, [])
        for a in attrs:
            aname = a.get('name')
            slug = re.sub('[^0-9a-z]+', '_', (aname or '').lower())
            key = f'sc_{slug}'
            val = (request.form.get(key) or '').strip()
            if a.get('required') and not val:
                flash(f"Missing required class attribute: {aname}", 'error')
                return redirect(url_for('view_stock_material', stock_id=mat.id))
            class_values[aname] = val
        mat.class_attrs_json = json.dumps(class_values) if class_values else None

    db.session.commit()
    flash('Stock material updated.', 'ok')
    return redirect(url_for('view_stock_material', stock_id=mat.id))


@app.route('/stock/<int:stock_id>/upload', methods=['POST'])
@app.route('/lab/<lab_slug>/stock/<int:stock_id>/upload', methods=['POST'])
@login_required
def upload_stock_material_doc(stock_id, lab_slug=None):
    mat = StockMaterial.query.get_or_404(stock_id)
    if lab_slug:
        lab = get_lab_or_404(lab_slug)
        if mat.database_id != lab.id:
            abort(403)
        set_current_lab(lab)

    role = db_role(current_user, mat.database_id) if mat.database_id else None
    if role not in ('owner', 'admin', 'editor'):
        abort(403)

    file = request.files.get('file')
    if not file or file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('view_stock_material', stock_id=mat.id))
    if not allowed_file(file.filename):
        flash('File type not allowed.', 'error')
        return redirect(url_for('view_stock_material', stock_id=mat.id))
    folder = stock_material_upload_dir(mat.id)
    stored_path, _ = save_uploaded_file(file, folder)
    doc = StockMaterialDocument(
        stock_material_id=mat.id,
        filename=file.filename,
        stored_path=stored_path,
        mimetype=file.mimetype,
        uploaded_by_user_id=_uid(),
    )
    db.session.add(doc)
    db.session.commit()
    try:
        log_lab_event(mat.database, "document_uploaded", "stock_material", mat.id, file.filename, {"doc_id": doc.id})
    except Exception:
        pass
    flash('Document uploaded.', 'ok')
    return redirect(url_for('view_stock_material', stock_id=mat.id))


@app.route('/stock/doc/<int:doc_id>/download')
def download_stock_material_doc(doc_id):
    d = StockMaterialDocument.query.get_or_404(doc_id)
    return send_stored_file(d.stored_path, d.filename)


@app.post('/stock/doc/<int:doc_id>/delete')
@login_required
def delete_stock_material_doc(doc_id):
    d = StockMaterialDocument.query.get_or_404(doc_id)
    mat = d.stock_material
    role = db_role(current_user, mat.database_id) if mat.database_id else None
    if role not in ('owner', 'admin', 'editor'):
        abort(403)
    try:
        if d.stored_path and os.path.exists(d.stored_path):
            os.remove(d.stored_path)
    except Exception:
        pass
    filename = d.filename
    db.session.delete(d)
    db.session.commit()
    try:
        log_lab_event(mat.database, "document_deleted", "stock_material", mat.id, filename, {"doc_id": doc_id})
    except Exception:
        pass
    flash('Document deleted.', 'ok')
    return redirect(url_for('view_stock_material', stock_id=mat.id))


@app.context_processor
def inject_global_counts():
    return dict(global_counts={
        "projects": Project.query.count(),
        "samples": Sample.query.count(),
        "experiments": Experiment.query.count(),
    })


@app.context_processor
def lab_url_helpers():
    def lab_link(lab):
        if not lab:
            return '#'
        if getattr(lab, 'slug', None):
            return url_for('view_lab_by_slug', slug=lab.slug)
        return url_for('view_lab', db_id=lab.id)

    return dict(lab_link=lab_link)


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
    folder = sample_upload_dir(sample.id)
    stored_path, _ = save_uploaded_file(file, folder)
    doc = SampleDocument(
        sample_id=sample.id, filename=file.filename, stored_path=stored_path, mimetype=file.mimetype, uploaded_by_user_id=_uid()
    )
    db.session.add(doc)
    db.session.commit()
    try:
        log_lab_event(sample.project.database, "document_uploaded", "sample", sample.id, file.filename, {"doc_id": doc.id})
    except Exception:
        pass
    try:
        db.session.add(SampleLog(sample_id=sample.id, user_id=_uid(), title=f"Document uploaded: {file.filename}"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    flash("Document uploaded.", "ok")
    return redirect(url_for("view_sample", sample_id=sample.id))


@app.route("/sample/doc/<int:doc_id>/download")
def download_sample_doc(doc_id):
    d = SampleDocument.query.get_or_404(doc_id)
    return send_stored_file(d.stored_path, d.filename)


@app.post("/sample/doc/<int:doc_id>/delete")
@login_required
def delete_sample_doc(doc_id):
    d = SampleDocument.query.get_or_404(doc_id)
    sample = d.sample
    project = sample.project if sample else None
    role = db_role(current_user, project.database_id) if project and project.database_id else None
    if role not in ('owner', 'admin', 'editor'):
        abort(403)
    try:
        if d.stored_path and os.path.exists(d.stored_path):
            os.remove(d.stored_path)
    except Exception:
        pass
    filename = d.filename
    db.session.delete(d)
    db.session.commit()
    try:
        log_lab_event(project.database, "document_deleted", "sample", sample.id, filename, {"doc_id": doc_id})
    except Exception:
        pass
    try:
        db.session.add(SampleLog(sample_id=sample.id, user_id=_uid(), title=f"Document deleted: {filename}"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    flash("Document deleted.", "ok")
    return redirect(url_for("view_sample", sample_id=sample.id))


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

    # Sample class attributes (editable only when not inherited)
    class_attrs_inherited = False
    if sample.parent_id:
        class_attrs_inherited = True
    elif sample.stock_material and getattr(sample.stock_material, 'class_attrs_json', None):
        class_attrs_inherited = True

    sc = getattr(sample, 'sample_class', None)
    psc = getattr(sample, 'project_class', None)
    class_defs = []
    if sc and getattr(sc, 'attributes_json', None):
        base_attrs = safe_json_loads(sc.attributes_json, [])
        if psc and getattr(psc, 'attributes_override_json', None):
            override = safe_json_loads(psc.attributes_override_json, [])
            merged = []
            names = {a.get('name'): a for a in override if isinstance(a, dict)}
            for a in base_attrs:
                if isinstance(a, dict) and a.get('name') in names:
                    merged.append(names.pop(a.get('name')))
                else:
                    merged.append(a)
            merged.extend(names.values())
        else:
            merged = base_attrs
        class_defs = [a for a in merged if isinstance(a, dict) and a.get('name')]

    class_missing = []
    if class_defs and not class_attrs_inherited:
        class_values = {}
        for a in class_defs:
            aname = a.get('name')
            slug = re.sub('[^0-9a-z]+', '_', (aname or '').lower())
            key = f"sc_{slug}"
            val = (request.form.get(key) or "").strip()
            if a.get('required') and not val:
                class_missing.append(aname)
            class_values[aname] = val
        if class_missing:
            flash("Missing required class attributes: " + ", ".join(class_missing), "error")
            return redirect(url_for("view_sample", sample_id=sample.id))
        sample.class_attrs_json = json.dumps(class_values) if class_values else None

    attrs = get_project_attrs(sample.project_id)
    existing = {v.attribute_id: v for v in sample.attribute_values}

    missing_required = []
    for a in attrs:
        key = f"attr_{a.id}"
        if getattr(a, 'inherited', False) and sample.parent_id:
            root = get_sample_root(sample)
            pav = SampleAttributeValue.query.filter_by(sample_id=root.id, attribute_id=a.id).first()
            val = pav.value if pav else ""
        else:
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


@app.route("/sample/<int:sample_id>/qr")
@login_required
def sample_qr(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    if sample.project and sample.project.database:
        lab_key = sample.project.database.slug or str(sample.project.database.id)
        url = url_for("view_sample", lab_slug=lab_key, project_id=sample.project.id, sample_id=sample.id, _external=True)
    else:
        url = url_for("view_sample", sample_id=sample.id, _external=True)
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/stock/<int:stock_id>/qr")
@login_required
def stock_qr(stock_id):
    mat = StockMaterial.query.get_or_404(stock_id)
    if mat.database:
        lab_key = mat.database.slug or str(mat.database.id)
        url = url_for("view_stock_material", lab_slug=lab_key, stock_id=mat.id, _external=True)
    else:
        url = url_for("view_stock_material", stock_id=mat.id, _external=True)
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/equipment/<int:equipment_id>/qr")
@login_required
def equipment_qr(equipment_id):
    eq = Equipment.query.get_or_404(equipment_id)
    eq_lab = eq.database or (eq.project.database if eq.project else None)
    if eq_lab:
        lab_key = eq_lab.slug or str(eq_lab.id)
        url = url_for("view_equipment", lab_slug=lab_key, equipment_id=eq.id, _external=True)
    else:
        url = url_for("view_equipment", equipment_id=eq.id, _external=True)
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


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
    add_column_if_missing("project", "slug",          "slug VARCHAR(160)")
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

    # Calibration logs type
    add_column_if_missing("calibration_log", "calibration_type", "calibration_type TEXT")

    # Calibration routine standard
    add_column_if_missing("calibration_routine", "standard", "standard TEXT")
    # Stock material sample class linking
    add_column_if_missing("stock_material", "sample_class_id", "sample_class_id INTEGER")
    add_column_if_missing("stock_material", "original_quantity", "original_quantity FLOAT")
    add_column_if_missing("database", "time_zone", "time_zone VARCHAR(64)")
    add_column_if_missing("database", "role_badge_owner", "role_badge_owner VARCHAR(32)")
    add_column_if_missing("database", "role_badge_admin", "role_badge_admin VARCHAR(32)")
    add_column_if_missing("database", "role_badge_editor", "role_badge_editor VARCHAR(32)")
    add_column_if_missing("database", "role_badge_viewer", "role_badge_viewer VARCHAR(32)")
    add_column_if_missing("facility", "manager_user_id", "manager_user_id INTEGER")
    add_column_if_missing("facility", "address_line1", "address_line1 VARCHAR(200)")
    add_column_if_missing("facility", "address_line2", "address_line2 VARCHAR(200)")
    add_column_if_missing("facility", "city", "city VARCHAR(120)")
    add_column_if_missing("facility", "state", "state VARCHAR(120)")
    add_column_if_missing("facility", "postal_code", "postal_code VARCHAR(40)")
    add_column_if_missing("facility", "country", "country VARCHAR(120)")
    add_column_if_missing("user", "title", "title VARCHAR(120)")
    add_column_if_missing("user", "phone", "phone VARCHAR(64)")
    add_column_if_missing("user", "organization", "organization VARCHAR(160)")
    add_column_if_missing("user", "bio", "bio TEXT")

    # Attributes / values
    add_column_if_missing("project_sample_attribute", "unit", "unit TEXT")
    add_column_if_missing("project_sample_attribute", "inherited", "inherited BOOLEAN")
    add_column_if_missing("sample_attribute_value",
                          "is_placeholder", "is_placeholder BOOLEAN")
    add_column_if_missing("sample_attribute_value",
                          "updated_at",     "updated_at DATETIME")


if __name__ == "__main__":
    app.run(debug=True)
