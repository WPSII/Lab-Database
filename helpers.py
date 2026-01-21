import json
import os
import re

from flask import send_from_directory
from werkzeug.utils import secure_filename


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


def safe_slug(value: str, max_len: int = 40) -> str:
    s = (value or '').strip()
    if not s:
        return ''
    s2 = re.sub(r"[^0-9a-zA-Z]+", '-', s).strip('-').lower()
    return s2[:max_len]


def save_uploaded_file(file, folder: str) -> tuple[str, str]:
    safe_name = secure_filename(file.filename)
    stored_path = os.path.join(folder, safe_name)
    base, ext = os.path.splitext(safe_name)
    i = 1
    while os.path.exists(stored_path):
        safe_name = f"{base}({i}){ext}"
        stored_path = os.path.join(folder, safe_name)
        i += 1
    file.save(stored_path)
    return stored_path, safe_name


def send_stored_file(stored_path: str, download_name: str):
    return send_from_directory(
        os.path.dirname(stored_path),
        os.path.basename(stored_path),
        as_attachment=True,
        download_name=download_name,
    )


# --- Sample lineage helpers ---

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


# --- Experiment lineage helpers ---

def get_full_experiment_chain(exp):
    """Return [root ... selected] for the given experiment."""
    chain = []
    cur = exp
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


# --- Tree serialization helpers ---

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


def serialize_experiment_tree(node, current_id):
    kids = sorted(node.children, key=lambda e: (e.title or "").lower())
    return {
        "id": node.id,
        "title": node.title,
        "is_current": node.id == current_id,
        "children": [serialize_experiment_tree(c, current_id) for c in kids],
    }


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
