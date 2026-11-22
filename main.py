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

app = FastAPI(title="SatyaNirman AI - National Infrastructure & Fund Auditor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

DB_NAME = "satyanirman_v2.db"


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
            14500000.0,  # ₹1.45 Cr
            11600000.0,  # ₹1.16 Cr released (80%)
            34.0,  # CV detects 34% physical work
            4930000.0,  # ₹49.3 Lakhs actual value
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
            6800000.0,  # ₹68 Lakhs
            4080000.0,  # ₹40.8 Lakhs released (60%)
            64.0,  # CV detects 64% physical work
            4352000.0,  # ₹43.52 Lakhs actual value
            "
