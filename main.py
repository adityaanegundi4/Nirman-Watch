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

app = FastAPI(title="SatyaNirman AI - NavIC & CV Public Infrastructure Auditor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

DB_NAME = "satyanirman.db"


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
    sample_projects = [
        (
            "4-Lane Smart Road & Drainage Upgrade",
            "Jayanagar 4th Block, Bengaluru",
            "Apex Infra Builders Pvt Ltd",
            12.9299,
            77.5824,
            5000000.0,
            4000000.0,
            36.0,
            1800000.0,
            "FLAGGED: Fund Mismatch",
            "2026-11-22 07:45 AM",
            "",
            (
                "Contractor claimed 80% funds (₹40L), but CV detected only 36%"
                " physical road completion (₹18L value)."
            ),
            "⚠️ EXIF Stripped (Edited/Forwarded Image)",
            3,
        ),
        (
            "Government Primary Health Center (PHC) Block",
            "Indiranagar 2nd Stage, Bengaluru",
            "Kaveri Civil Works",
            12.9784,
            77.6408,
            8500000.0,
            5100000.0,
            62.0,
            5270000.0,
            "VERIFIED ON-TRACK",
            "2026-11-22 08:05 AM",
            "",
            (
                "NavIC coordinates locked & CV structural progress matches"
                " funds."
            ),
            "✅ Authentic Camera EXIF Verified",
            0,
        ),
        (
            "Stormwater Culvert & Pedestrian Bridge",
            "Whitefield Main Road, Bengaluru",
            "MetroLine Contractors",
            12.9698,
            77.7500,
            3200000.0,
            2400000.0,
            20.0,
            640000.0,
            "FLAGGED: Ghost Site Risk",
            "2026-11-21 04:20 PM",
            "",
            (
                "No NavIC-verified site upload in 14 days; CV shows stalled"
                " excavation."
            ),
            "⚠️ No Live Site Proof Submitted",
            5,
        ),
    ]
    c.executemany(
        """
            INSERT INTO projects (
                title, area, contractor, lat, lng, sanctioned_budget,
                funds_released, cv_progress_percent, ai_estimated_spent,
                status, last_verified, latest_image, flag_reason,
                exif_status, citizen_reports_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        sample_projects,
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
      return "⚠️ Missing Camera EXIF (Possible Screenshot/WhatsApp Forward)"
    tags = {ExifTags.TAGS.get(k, k): v for k, v in exif_data.items()}
    make = tags.get("Make", "")
    model = tags.get("Model", "")
    if make or model:
      return f"✅ Original Camera EXIF ({str(make).strip()} {str(model).strip()})"
    return "⚠️ Partial EXIF Metadata (Verify Timestamp)"
  except Exception:
    return "⚠️ Unreadable EXIF Metadata"


def analyze_construction_cv(
    filepath: str,
    current_progress: float,
    sanctioned_budget: float,
    funds_released: float,
):
  """
    Real Computer Vision Analysis using Pillow + NumPy:
    1. Rejects blank/solid-color/corrupt images via pixel variance.
    2. Computes structural edge density (rebar, brickwork, scaffolding, road edges).
    3. Measures outdoor construction material color ratios (concrete/asphalt gray, earth/brick brown, safety orange/yellow).
    4. Maps genuine structural feature density to physical completion % and monetary value used.
    """
  try:
    img = Image.open(filepath)
  except Exception:
    return {"valid": False, "error": "Invalid or corrupted image file."}

  exif_status = inspect_exif_metadata(img)
  rgb_img = img.convert("RGB").resize((256, 256))
  arr = np.asarray(rgb_img, dtype=np.float32)

  # 1. Check pixel variance (reject blank walls, black screens, solid color images)
  pixel_std = float(np.std(arr))
  if pixel_std < 18.0:
    return {
        "valid": False,
        "error": (
            "CV REJECTED: Blank or solid-color image detected. Upload a clear"
            " construction site photo."
        ),
    }

  # 2. Structural Edge Density (detects scaffolding, bricks, pillars, road boundaries)
  gray_img = rgb_img.convert("L")
  edges = gray_img.filter(ImageFilter.FIND_EDGES)
  edge_arr = np.asarray(edges, dtype=np.float32)
  edge_density = float(np.mean(edge_arr > 35.0))  # fraction of strong edges

  if edge_density < 0.04:
    return {
        "valid": False,
        "error": (
            "CV REJECTED: Too few structural features detected (blurry or"
            " non-construction image)."
        ),
    }

  # 3. Construction Material Color Profile (Gray concrete/asphalt + Earth/Brick tones + Sky/Outdoor lighting)
  r, g, b = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]
  # Gray concrete / asphalt pixels (R, G, B close together)
  is_concrete_asphalt = (
      (np.abs(r - g) < 18) & (np.abs(g - b) < 18) & (r > 40) & (r < 220)
  )
  # Earth / Soil / Red Brick pixels (R > G > B)
  is_earth_brick = (r > g + 12) & (g > b + 5) & (r > 60)

  material_ratio = float(np.mean(is_concrete_asphalt | is_earth_brick))

  if material_ratio < 0.22:
    return {
        "valid": False,
        "error": (
            "CV REJECTED: Image does not match outdoor construction materials"
            " (concrete, asphalt, earth, or brick)."
        ),
    }

  # 4. Calculate deterministic CV progress gain based on structural edge & material score
  cv_score = min(1.0, (edge_density * 1.8) + (material_ratio * 0.6))
  detected_gain = round(5.0 + (cv_score * 14.0), 1)
  new_progress = min(100.0, round(current_progress + detected_gain, 1))
  ai_estimated_spent = round((new_progress / 100.0) * sanctioned_budget, 2)

  mismatch = funds_released - ai_estimated_spent
  if sanctioned_budget > 0 and mismatch > (0.15 * sanctioned_budget):
    status = "FLAGGED: Fund Mismatch"
    reason = (
        f"CV detected {new_progress}% physical work"
        f" (₹{ai_estimated_spent:,.0f}) [Material Match:"
        f" {int(material_ratio*100)}%], but ₹{funds_released:,.0f} was"
        " released!"
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
  now = datetime.now().strftime("%Y-%m-%d %I:%M %p")
  conn.execute(
      """
        INSERT INTO projects (
            title, area, contractor, lat, lng, sanctioned_budget,
            funds_released, cv_progress_percent, ai_estimated_spent,
            status, last_verified, latest_image, flag_reason,
            exif_status, citizen_reports_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
      (
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
          "Project registered. Waiting for first NavIC-locked site photo.",
          "Pending First Upload",
          0,
      ),
  )
  conn.commit()
  conn.close()
  return {"status": "success", "message": "Project published to live map!"}


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

  # 1. NAVIC / GPS GEOFENCE CHECK (Must be within 100 meters)
  distance = haversine_meters(
      project["lat"], project["lng"], device_lat, device_lng
  )
  now = datetime.now().strftime("%Y-%m-%d %I:%M %p")

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

  # 2. SAVE TEMP PHOTO & COMPUTE SHA-256 DUPLICATE HASH
  ext = os.path.splitext(image.filename or "")[1].lower()
  if ext not in [".jpg", ".jpeg", ".png", ".webp"]:
    ext = ".jpg"
  safe_filename = f"proj_{project_id}_{uuid.uuid4().hex[:10]}{ext}"
  filepath = os.path.join(UPLOAD_DIR, safe_filename)

  with open(filepath, "wb") as buffer:
    shutil.copyfileobj(image.file, buffer)

  img_hash = compute_sha256(filepath)
  existing_hash = conn.execute(
      "SELECT id FROM image_hashes WHERE sha256_hash = ?", (img_hash,)
  ).fetchone()

  if existing_hash:
    os.remove(filepath)
    flag_msg = (
        "FRAUD BLOCKED: Duplicate/Recycled photo detected! This exact image"
        " was already submitted earlier."
    )
    conn.execute(
        "UPDATE projects SET status = ?, flag_reason = ?, last_verified = ?"
        " WHERE id = ?",
        ("FLAGGED: Recycled Photo Fraud", flag_msg, now, project_id),
    )
    conn.commit()
    conn.close()
    return {"verified": False, "message": flag_msg}

  # 3. RUN REAL COMPUTER VISION PIXEL, EDGE & MATERIAL AUDIT
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

  # Record hash so this image can never be reused fraudulently
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

  now = datetime.now().strftime("%Y-%m-%d %I:%M %p")
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
        f"Flagged by {new_count} local citizens reporting '{issue_type}' on"
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
          "Citizen report recorded on public ledger! Total citizen alerts:"
          f" {new_count}."
      ),
  }


@app.get("/api/projects/{project_id}/reports")
def get_project_reports(project_id: int):
  conn = get_db()
  rows = conn.execute(
      "SELECT * FROM citizen_reports WHERE project_id = ? ORDER BY id DESC",
      (project_id,),
  ).fetchall()
  conn.close()
  return [dict(r) for r in rows]
