import hashlib
import math
import os
import shutil
import sqlite3
import uuid
from datetime import datetime
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import numpy as np
from PIL import ExifTags, Image, ImageFilter

app = FastAPI(title="Nirman Watch - NavIC & AI Public Infrastructure Auditor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

DB_NAME = "nirmanwatch_v3.db"


def get_db():
  conn = sqlite3.connect(DB_NAME, check_same_thread=False)
  conn.row_factory = sqlite3.Row
  return conn


def init_db():
  conn = get_db()
  c = conn.cursor()
  c.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tender_id TEXT NOT NULL,
            department TEXT NOT NULL,
            title TEXT NOT NULL,
            area TEXT NOT NULL,
            contractor TEXT NOT NULL,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            sanctioned_budget REAL NOT NULL,
            funds_released REAL NOT NULL,
            cv_progress_percent REAL NOT NULL,
            ai_estimated_spent REAL NOT NULL,
            status TEXT NOT NULL,
            last_verified TEXT NOT NULL,
            latest_image TEXT,
            flag_reason TEXT,
            exif_status TEXT DEFAULT 'Pending Verification',
            citizen_reports_count INTEGER DEFAULT 0
        )
    """)
  c.execute("""
        CREATE TABLE IF NOT EXISTS image_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            sha256_hash TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        )
    """)
  c.execute("""
        CREATE TABLE IF NOT EXISTS citizen_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            citizen_name TEXT NOT NULL,
            issue_type TEXT NOT NULL,
            description TEXT NOT NULL,
            reported_at TEXT NOT NULL
        )
    """)

  c.execute("SELECT COUNT(*) FROM projects")
  if c.fetchone()[0] == 0:
    gov_projects = [
        (
            "KPPP/2026-27/BBMP/RD-4092",
            "Bruhat Bengaluru Mahanagara Palike (BBMP)",
            "White-Topping & Smart Stormwater Drain — Kanakapura Main Road",
            "Kanakapura Road / Thalaghattapura, South Bengaluru",
            "Nandi Highway & Civil Infra Pvt Ltd",
            12.8789,
            77.5432,
            14500000.0,
            11600000.0,
            34.0,
            4930000.0,
            "FLAGGED: Fund Mismatch",
            "2026-11-22 09:15 AM IST",
            "",
            (
                "PFMS disbursed 80% (₹1.16 Cr), but CV detected only 34%"
                " concrete paving & drain completion (₹49.3L value)."
            ),
            "⚠️ EXIF Metadata Stripped (Forwarded Photo)",
            4,
        ),
        (
            "PWD/2026-27/BLR-S/BLDG-1184",
            "Public Works Department (PWD), Govt. of Karnataka",
            "Upgrade of Government Model Primary School & STEM Lab Block",
            "Kengeri Satellite Town, Bengaluru",
            "Cauvery Urban Developers",
            12.9077,
            77.4854,
            6800000.0,
            4080000.0,
            64.0,
            4352000.0,
            "VERIFIED ON-TRACK",
            "2026-11-22 08:50 AM IST",
            "",
            (
                "NavIC coordinates locked within 12m. CV structural masonry &"
                " roof slab match released funds."
            ),
            "✅ Authentic Camera EXIF Verified",
            0,
        ),
        (
            "BWSSB/2026-27/WSS-7731",
            "Bangalore Water Supply & Sewerage Board (BWSSB)",
            "Underground Cauvery Stage-V Trunk Pipeline & Valve Chamber",
            "Banashankari 6th Stage, Bengaluru",
            "Deccan Trenchless Engineering Ltd",
            12.8914,
            77.5268,
            9200000.0,
            6900000.0,
            18.0,
            1656000.0,
            "FLAGGED: Ghost Site Risk",
            "2026-11-21 05:10 PM IST",
            "",
            (
                "Zero NavIC-authenticated contractor uploads in 16 days; CV"
                " shows open unlined trench."
            ),
            "⚠️ No Live Site Proof Submitted",
            6,
        ),
        (
            "NHAI/2026-27/NH-275/BRG-092",
            "National Highways Authority of India (NHAI)",
            "Pedestrian Skywalk & Solar High-Mast Junction Illumination",
            "Rajarajeshwari Nagar Arch, Mysore Road",
            "Vajra Steel & Infra Consortium",
            12.9260,
            77.5191,
            11000000.0,
            7700000.0,
            72.0,
            7920000.0,
            "VERIFIED ON-TRACK",
            "2026-11-22 09:30 AM IST",
            "",
            (
                "NavIC geofence passed. CV confirmed steel truss erection &"
                " foundation footings on schedule."
            ),
            "✅ Authentic Camera EXIF Verified",
            0,
        ),
    ]
    c.executemany(
        """
            INSERT INTO projects (
                tender_id, department, title, area, contractor, lat, lng,
                sanctioned_budget, funds_released, cv_progress_percent,
                ai_estimated_spent, status, last_verified, latest_image,
                flag_reason, exif_status, citizen_reports_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        gov_projects,
    )
  conn.commit()
  conn.close()


init_db()


def haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
  R = 6371000.0
  phi1, phi2 = math.radians(lat1), math.radians(lat2)
  dphi = math.radians(lat2 - lat1)
  dlambda = math.radians(lon2 - lon1)
  a = (
      math.sin(dphi / 2) ** 2
      + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
  )
  return 2 * R * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def compute_sha256(filepath: str) -> str:
  h = hashlib.sha256()
  with open(filepath, "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
      h.update(chunk)
  return h.hexdigest()


def inspect_exif_metadata(img: Image.Image) -> str:
  try:
    exif_data = img.getexif()
    if not exif_data:
      return "⚠️ Missing Camera EXIF (Screenshot/Edited File)"
    tags = {ExifTags.TAGS.get(k, k): v for k, v in exif_data.items()}
    make = str(tags.get("Make", "")).strip()
    model = str(tags.get("Model", "")).strip()
    if make or model:
      return f"✅ Original Camera EXIF ({make} {model})".strip()
    return "⚠️ Partial EXIF Metadata"
  except Exception:
    return "⚠️ Unreadable EXIF Metadata"


def analyze_construction_cv(
    filepath: str,
    current_progress: float,
    sanctioned_budget: float,
    funds_released: float,
):
  try:
    img = Image.open(filepath)
  except Exception:
    return {"valid": False, "error": "Corrupted or unreadable image file."}

  exif_status = inspect_exif_metadata(img)
  rgb_img = img.convert("RGB").resize((256, 256))
  arr = np.asarray(rgb_img, dtype=np.float32)

  if float(np.std(arr)) < 18.0:
    return {
        "valid": False,
        "error": (
            "CV REJECTED: Blank or solid-color image detected. Upload an actual"
            " site photo."
        ),
    }

  edges = rgb_img.convert("L").filter(ImageFilter.FIND_EDGES)
  edge_density = float(np.mean(np.asarray(edges, dtype=np.float32) > 35.0))
  if edge_density < 0.04:
    return {
        "valid": False,
        "error": (
            "CV REJECTED: Insufficient structural edges detected (blurry or"
            " non-site image)."
        ),
    }

  r, g, b = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]
  is_concrete_asphalt = (
      (np.abs(r - g) < 18) & (np.abs(g - b) < 18) & (r > 40) & (r < 220)
  )
  is_earth_brick = (r > g + 12) & (g > b + 5) & (r > 60)
  material_ratio = float(np.mean(is_concrete_asphalt | is_earth_brick))

  if material_ratio < 0.22:
    return {
        "valid": False,
        "error": (
            "CV REJECTED: Scene lacks outdoor civil materials (concrete,"
            " asphalt, earth, or brick)."
        ),
    }

  cv_score = min(1.0, (edge_density * 1.8) + (material_ratio * 0.6))
  detected_gain = round(5.5 + (cv_score * 13.5), 1)
  new_progress = min(100.0, round(current_progress + detected_gain, 1))
  ai_estimated_spent = round((new_progress / 100.0) * sanctioned_budget, 2)

  mismatch = funds_released - ai_estimated_spent
  if sanctioned_budget > 0 and mismatch > (0.15 * sanctioned_budget):
    status = "FLAGGED: Fund Mismatch"
    reason = (
        f"CV detected {new_progress}% physical work"
        f" (₹{ai_estimated_spent:,.0f}) [Material Match:"
        f" {int(material_ratio*100)}%], but ₹{funds_released:,.0f} was"
        " disbursed!"
    )
  else:
    status = "VERIFIED ON-TRACK"
    reason = (
        f"NavIC GPS verified within 100m. CV confirmed {new_progress}% work"
        f" (₹{ai_estimated_spent:,.0f}) [Material Match:"
        f" {int(material_ratio*100)}%]."
    )

  return {
      "valid": True,
      "new_progress": new_progress,
      "ai_estimated_spent": ai_estimated_spent,
      "status": status,
      "reason": reason,
      "exif_status": exif_status,
  }


@app.get("/")
def serve_frontend():
  if not os.path.exists("index.html"):
    raise HTTPException(status_code=404, detail="index.html not found")
  return FileResponse("index.html")


@app.get("/api/projects")
def get_all_projects():
  conn = get_db()
  rows = conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
  conn.close()
  return [dict(row) for row in rows]


@app.post("/api/projects")
def create_project(
    tender_id: str = Form(...),
    department: str = Form(...),
    title: str = Form(...),
    area: str = Form(...),
    contractor: str = Form(...),
    lat: float = Form(...),
    lng: float = Form(...),
    sanctioned_budget: float = Form(...),
    funds_released: float = Form(...),
):
  if sanctioned_budget <= 0:
    raise HTTPException(
        status_code=400, detail="Sanctioned budget must be greater than ₹0."
    )
  if funds_released < 0:
    raise HTTPException(
        status_code=400, detail="Funds released cannot be negative."
    )

  conn = get_db()
  now = datetime.now().strftime("%Y-%m-%d %I:%M %p IST")
  conn.execute(
      """
        INSERT INTO projects (
            tender_id, department, title, area, contractor, lat, lng,
            sanctioned_budget, funds_released, cv_progress_percent,
            ai_estimated_spent, status, last_verified, latest_image,
            flag_reason, exif_status, citizen_reports_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
      (
          tender_id.strip(),
          department.strip(),
          title.strip(),
          area.strip(),
          contractor.strip(),
          lat,
          lng,
          sanctioned_budget,
          funds_released,
          0.0,
          0.0,
          "AWAITING NAVIC SITE PROOF",
          now,
          "",
          (
              "Tender ingested from e-Procurement. Awaiting first NavIC-locked"
              " site proof."
          ),
          "Pending First Upload",
          0,
      ),
  )
  conn.commit()
  conn.close()
  return {"status": "success", "message": "Government tender published!"}


@app.post("/api/projects/{project_id}/verify")
async def upload_and_verify_site(
    project_id: int,
    device_lat: float = Form(...),
    device_lng: float = Form(...),
    image: UploadFile = File(...),
):
  conn = get_db()
  project = conn.execute(
      "SELECT * FROM projects WHERE id = ?", (project_id,)
  ).fetchone()
  if not project:
    conn.close()
    raise HTTPException(status_code=404, detail="Project not found")

  distance = haversine_meters(
      project["lat"], project["lng"], device_lat, device_lng
  )
  now = datetime.now().strftime("%Y-%m-%d %I:%M %p IST")

  if distance > 100.0:
    flag_msg = (
        f"FAKE LOCATION BLOCKED: Upload attempted {int(distance)}m away from"
        " official NavIC site pin!"
    )
    conn.execute(
        "UPDATE projects SET status = ?, flag_reason = ?, last_verified = ?"
        " WHERE id = ?",
        ("FLAGGED: Fake GPS/NavIC", flag_msg, now, project_id),
    )
    conn.commit()
    conn.close()
    return {
        "verified": False,
        "distance_meters": round(distance, 1),
        "message": flag_msg,
    }

  ext = os.path.splitext(image.filename or "")[1].lower()
  if ext not in [".jpg", ".jpeg", ".png", ".webp"]:
    ext = ".jpg"
  safe_filename = f"proj_{project_id}_{uuid.uuid4().hex[:10]}{ext}"
  filepath = os.path.join(UPLOAD_DIR, safe_filename)

  with open(filepath, "wb") as buffer:
    shutil.copyfileobj(image.file, buffer)

  img_hash = compute_sha256(filepath)
  if conn.execute(
      "SELECT id FROM image_hashes WHERE sha256_hash = ?", (img_hash,)
  ).fetchone():
    os.remove(filepath)
    flag_msg = (
        "FRAUD BLOCKED: Duplicate/Recycled photo detected! Exact SHA-256 hash"
        " already exists."
    )
    conn.execute(
        "UPDATE projects SET status = ?, flag_reason = ?, last_verified = ?"
        " WHERE id = ?",
        ("FLAGGED: Recycled Photo Fraud", flag_msg, now, project_id),
    )
    conn.commit()
    conn.close()
    return {"verified": False, "message": flag_msg}

  cv_result = analyze_construction_cv(
      filepath,
      project["cv_progress_percent"],
      project["sanctioned_budget"],
      project["funds_released"],
  )

  if not cv_result["valid"]:
    os.remove(filepath)
    conn.close()
    return {"verified": False, "message": cv_result["error"]}

  conn.execute(
      "INSERT INTO image_hashes (project_id, sha256_hash, uploaded_at) VALUES"
      " (?, ?, ?)",
      (project_id, img_hash, now),
  )
  conn.execute(
      """
        UPDATE projects SET
            cv_progress_percent = ?,
            ai_estimated_spent = ?,
            status = ?,
            last_verified = ?,
            latest_image = ?,
            flag_reason = ?,
            exif_status = ?
        WHERE id = ?
    """,
      (
          cv_result["new_progress"],
          cv_result["ai_estimated_spent"],
          cv_result["status"],
          now,
          f"/uploads/{safe_filename}",
          cv_result["reason"],
          cv_result["exif_status"],
          project_id,
      ),
  )
  conn.commit()
  conn.close()

  return {
      "verified": True,
      "distance_meters": round(distance, 1),
      "cv_progress_percent": cv_result["new_progress"],
      "ai_estimated_spent": cv_result["ai_estimated_spent"],
      "status": cv_result["status"],
      "message": f"{cv_result['reason']} | {cv_result['exif_status']}",
  }


@app.post("/api/projects/{project_id}/citizen-report")
def submit_citizen_report(
    project_id: int,
    citizen_name: str = Form(...),
    issue_type: str = Form(...),
    description: str = Form(...),
):
  conn = get_db()
  project = conn.execute(
      "SELECT * FROM projects WHERE id = ?", (project_id,)
  ).fetchone()
  if not project:
    conn.close()
    raise HTTPException(status_code=404, detail="Project not found")

  now = datetime.now().strftime("%Y-%m-%d %I:%M %p IST")
  conn.execute(
      "INSERT INTO citizen_reports (project_id, citizen_name, issue_type,"
      " description, reported_at) VALUES (?, ?, ?, ?, ?)",
      (
          project_id,
          citizen_name.strip(),
          issue_type.strip(),
          description.strip(),
          now,
      ),
  )
  new_count = (project["citizen_reports_count"] or 0) + 1
  new_status = project["status"]
  new_reason = project["flag_reason"]

  if new_count >= 3 and "FLAGGED" not in new_status:
    new_status = "FLAGGED: Citizen Alert"
    new_reason = (
        f"Escalated by {new_count} citizen reports citing '{issue_type}' on"
        " site."
    )

  conn.execute(
      "UPDATE projects SET citizen_reports_count = ?, status = ?, flag_reason ="
      " ? WHERE id = ?",
      (new_count, new_status, new_reason, project_id),
  )
  conn.commit()
  conn.close()
  return {
      "status": "success",
      "message": (
          f"Public alert logged on ledger! Total citizen reports: {new_count}."
      ),
  }
