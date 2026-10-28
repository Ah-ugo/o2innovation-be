"""O2 Innovations Lab API. Run: uvicorn main:app --reload"""
import os, secrets, time, jwt, random, re
from datetime import datetime, timedelta
from typing import Literal, Optional
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
db = AsyncIOMotorClient(MONGO_URL).o2lab
SECRET = os.getenv("JWT_SECRET", "dev")
pwd = CryptContext(schemes=["bcrypt"])
bearer = HTTPBearer()

app = FastAPI(title="O2 Innovations Lab - E-Learning Platform")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def oid(x):
    try:
        return ObjectId(x)
    except Exception:
        raise HTTPException(400, "Invalid ID format.")

async def find_course(x):
    try:
        c = await db.courses.find_one({"_id": ObjectId(x)})
    except Exception:
        c = None
    return c or await db.courses.find_one({"slug": x})

def out(d):
    if not d:
        return None
    res = dict(d)
    if "_id" in res:
        res["id"] = str(res.pop("_id"))
    elif "id" in res:
        res["id"] = str(res["id"])
    res.pop("password", None)
    return res

def token(u):
    return jwt.encode(
        {"sub": str(u["_id"]), "role": u.get("role", "student"), "name": u.get("name", ""), "exp": time.time() + 7 * 86400},
        SECRET,
        algorithm="HS256"
    )

async def user(c=Depends(bearer)):
    try:
        p = jwt.decode(c.credentials, SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, "Session expired. Sign in again.")
    u = await db.users.find_one({"_id": ObjectId(p["sub"])})
    if not u:
        raise HTTPException(401, "Account not found.")
    return u

async def admin(u=Depends(user)):
    if u.get("role") != "admin":
        raise HTTPException(403, "Admins only.")
    return u

# --- Email Notifications Service ---
async def send_email(to_email: str, subject: str, body_text: str, email_type: str = "general"):
    """
    Logs email to db.emails outbox and optionally sends via SMTP if credentials are configured.
    Always records full email content for admin inspection.
    """
    record = {
        "to": to_email,
        "subject": subject,
        "body": body_text,
        "type": email_type,
        "sent_at": datetime.utcnow().isoformat(),
        "status": "delivered"
    }
    # Check if SMTP configuration exists
    smtp_host = os.getenv("SMTP_HOST")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))

    if smtp_host and smtp_user and smtp_pass:
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(body_text, "html")
            msg["Subject"] = subject
            msg["From"] = os.getenv("SMTP_FROM", "O2 Campus <campus@o2lab.ng>")
            msg["To"] = to_email
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            record["status"] = "sent_via_smtp"
        except Exception as e:
            record["status"] = f"smtp_error: {str(e)}"
    
    await db.emails.insert_one(record)
    return record

# --- Models ---
class Login(BaseModel):
    email: EmailStr
    password: str

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    code: str
    new_password: str

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    bio: Optional[str] = None
    avatar: Optional[str] = None

class Application(BaseModel):
    full_name: str
    email: EmailStr
    phone: str
    course_id: str
    mode: Literal["onsite", "online"]
    message: Optional[str] = None

class ManualEnroll(BaseModel):
    name: str
    email: EmailStr
    course_id: str
    phone: Optional[str] = ""

class BulkImport(BaseModel):
    students: list[ManualEnroll]

class LessonQuestion(BaseModel):
    q: str
    options: list[str]
    answer: int
    explanation: Optional[str] = ""

class Lesson(BaseModel):
    title: str
    kind: Literal["live", "recorded"]
    url: str  # Google Meet link (live) or YouTube/Cloudinary URL (recorded)
    starts_at: Optional[str] = None
    module: str = "Module 1"
    description: str = ""
    minutes: int = 0
    resources: list[str] = []
    quiz: list[LessonQuestion] = []
    assignment: Optional[str] = None  # Assignment prompt/instructions

class Question(BaseModel):
    q: str
    options: list[str]
    answer: int
    explanation: Optional[str] = ""

class Course(BaseModel):
    title: str
    summary: str
    price: int
    modes: list[Literal["onsite", "online"]] = ["onsite", "online"]
    thumbnail: Optional[str] = None
    lessons: list[Lesson] = []
    quiz: list[Question] = []  # Question bank for final test
    pass_mark: int = 70
    time_limit_minutes: int = 20
    attempt_limit: int = 3
    quiz_bank_sample_size: Optional[int] = None
    slug: Optional[str] = None
    level: str = "Beginner"
    instructor: str = "O2 Lab Instructors"
    instructor_bio: Optional[str] = "Senior engineers and mentors at O2 Innovations Lab."
    language: str = "English"
    what_you_learn: list[str] = []
    requirements: list[str] = []

class Answers(BaseModel):
    answers: list[int]
    session_token: Optional[str] = None

class LessonQuizAnswer(BaseModel):
    answers: list[int]

class AssignmentSubmit(BaseModel):
    file_url: str
    notes: Optional[str] = ""

class AssignmentGrade(BaseModel):
    grade: str
    score: int
    feedback: str

class Post(BaseModel):
    text: str
    lesson: Optional[int] = None

class Rate(BaseModel):
    stars: int
    comment: str = ""

class AnnouncementCreate(BaseModel):
    title: str
    text: str
    course: str = "all"
    priority: Literal["normal", "urgent", "event"] = "normal"

# --- Authentication & User Endpoints ---

@app.post("/auth/login")
async def login(b: Login):
    u = await db.users.find_one({"email": b.email.lower().strip()})
    if not u or not pwd.verify(b.password, u["password"]):
        raise HTTPException(401, "Wrong email or password.")
    return {"token": token(u), "user": out(u)}

@app.get("/me")
async def me(u=Depends(user)):
    return out(u)

@app.put("/me/profile")
async def update_profile(b: ProfileUpdate, u=Depends(user)):
    updates = {}
    if b.name is not None: updates["name"] = b.name.strip()
    if b.phone is not None: updates["phone"] = b.phone.strip()
    if b.bio is not None: updates["bio"] = b.bio.strip()
    if b.avatar is not None: updates["avatar"] = b.avatar.strip()
    if updates:
        await db.users.update_one({"_id": u["_id"]}, {"$set": updates})
    updated = await db.users.find_one({"_id": u["_id"]})
    return out(updated)

@app.put("/me/password")
async def change_password(b: PasswordChange, u=Depends(user)):
    if not pwd.verify(b.current_password, u["password"]):
        raise HTTPException(400, "Current password does not match.")
    if len(b.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters.")
    await db.users.update_one({"_id": u["_id"]}, {"$set": {"password": pwd.hash(b.new_password)}})
    await send_email(
        u["email"],
        "Your O2 Campus Password Was Changed",
        f"<p>Hello {u.get('name', 'Learner')},</p><p>Your O2 Campus account password was successfully updated. If you did not make this change, please contact admin@o2lab.ng immediately.</p>",
        "password_changed"
    )
    return {"ok": True, "message": "Password updated successfully."}

@app.post("/auth/forgot-password")
async def forgot_password(b: ForgotPassword):
    u = await db.users.find_one({"email": b.email.lower().strip()})
    # Always return ok to prevent email enumeration, but send code if user exists
    if u:
        code = str(secrets.randbelow(900000) + 100000)
        exp = datetime.utcnow() + timedelta(minutes=30)
        await db.password_resets.delete_many({"email": u["email"]})
        await db.password_resets.insert_one({
            "email": u["email"],
            "code": code,
            "expires_at": exp,
            "used": False
        })
        await send_email(
            u["email"],
            "O2 Campus Password Reset Code",
            f"<p>Hello {u.get('name', 'Learner')},</p><p>Your password reset code is: <b style='font-size:24px;color:#010f6b;'>{code}</b></p><p>This code expires in 30 minutes. Use it on the password reset page to choose a new password.</p>",
            "password_reset"
        )
        return {"ok": True, "message": "Reset code sent to your email.", "preview_code": code}
    return {"ok": True, "message": "If an account exists with that email, a reset code was sent."}

@app.post("/auth/reset-password")
async def reset_password(b: ResetPassword):
    pr = await db.password_resets.find_one({
        "email": b.email.lower().strip(),
        "code": b.code.strip(),
        "used": False,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    if not pr:
        raise HTTPException(400, "Invalid or expired reset code.")
    if len(b.new_password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters.")
    
    await db.users.update_one({"email": b.email.lower().strip()}, {"$set": {"password": pwd.hash(b.new_password)}})
    await db.password_resets.update_one({"_id": pr["_id"]}, {"$set": {"used": True}})
    return {"ok": True, "message": "Password reset successfully. You can now log in."}

# --- Courses Public & Admin Endpoints ---

@app.get("/courses")
async def courses():
    res = []
    async for c in db.courses.find():
        item = out(c)
        item["quiz_count"] = len(item.get("quiz", []))
        item["lesson_count"] = len(item.get("lessons", []))
        item.pop("quiz", None)  # Don't expose quiz answers in public listing
        res.append(item)
    return res

@app.get("/courses/{id_or_slug}")
async def get_course(id_or_slug: str):
    c = await find_course(id_or_slug)
    if not c:
        raise HTTPException(404, "Course not found.")
    c_out = out(c)
    c_out["quiz_count"] = len(c_out.get("quiz", []))
    c_out.pop("quiz", None)
    return c_out

# --- Applications ---

@app.post("/applications")
async def apply(a: Application):
    r = await db.applications.insert_one(
        a.model_dump() | {
            "status": "pending",
            "created": datetime.utcnow().isoformat()
        }
    )
    # Notify admin
    await send_email(
        "admin@o2lab.ng",
        f"New Student Application: {a.full_name} ({a.mode})",
        f"<p>New application received from <b>{a.full_name}</b> ({a.email}, {a.phone}) for course <b>{a.course_id}</b> ({a.mode}).</p><p>Message: {a.message or 'None'}</p>",
        "admin_notification"
    )
    return {"id": str(r.inserted_id), "status": "pending"}

@app.get("/admin/applications")
async def apps(status: Optional[str] = None, _=Depends(admin)):
    query = {"status": status} if status and status != "all" else {}
    return [out(a) async for a in db.applications.find(query).sort("created", -1)]

@app.post("/admin/applications/{id}/approve")
async def approve(id: str, _=Depends(admin)):
    a = await db.applications.find_one({"_id": oid(id)})
    if not a:
        raise HTTPException(404, "Application not found.")
    
    target_course = await find_course(a["course_id"])
    if not target_course:
        target_course = await db.courses.find_one()
    
    temp = None
    u = await db.users.find_one({"email": a["email"].lower()})
    if not u:
        temp = secrets.token_urlsafe(8)
        r = await db.users.insert_one({
            "email": a["email"].lower(),
            "name": a["full_name"],
            "phone": a.get("phone", ""),
            "password": pwd.hash(temp),
            "role": "student",
            "created": datetime.utcnow().isoformat()
        })
        uid = r.inserted_id
    else:
        uid = u["_id"]
    
    if target_course:
        await db.enrollments.update_one(
            {"user": uid, "course": target_course["_id"]},
            {"$setOnInsert": {
                "completed": [],
                "score": None,
                "certificate": None,
                "attempts": [],
                "enrolled_at": datetime.utcnow().isoformat()
            }},
            upsert=True
        )
    
    await db.applications.update_one({"_id": a["_id"]}, {"$set": {"status": "approved"}})
    
    # Send credentials email to student
    course_name = target_course["title"] if target_course else "your chosen course"
    if temp:
        email_body = f"""
        <div style="font-family:sans-serif;line-height:1.6;color:#0a0e2a;">
            <h2 style="color:#010f6b;">Welcome to O2 Innovations Lab Campus!</h2>
            <p>Hello <b>{a['full_name']}</b>,</p>
            <p>Your application for <b>{course_name}</b> has been approved!</p>
            <p>Your online student account has been created with the following login details:</p>
            <div style="background:#f6f7fb;padding:16px;border-radius:8px;border:1px solid #ddd;margin:16px 0;">
                <p style="margin:4px 0;"><b>Portal Login:</b> <a href="http://localhost:3000/learn/login">http://localhost:3000/learn/login</a></p>
                <p style="margin:4px 0;"><b>Email:</b> {a['email']}</p>
                <p style="margin:4px 0;"><b>Temporary Password:</b> <code style="background:#ff8c1e;color:#0a0e2a;padding:2px 8px;border-radius:4px;font-weight:bold;">{temp}</code></p>
            </div>
            <p>Please log in and update your password under Account Settings.</p>
            <p>Happy learning,<br/><b>O2 Innovations Lab Team</b></p>
        </div>
        """
        await send_email(a["email"], f"Welcome to O2 Campus! Your Login Details for {course_name}", email_body, "student_credentials")
    
    return {"status": "approved", "temp_password": temp, "email": a["email"]}

@app.post("/admin/applications/{id}/reject")
async def reject(id: str, _=Depends(admin)):
    await db.applications.update_one({"_id": oid(id)}, {"$set": {"status": "rejected"}})
    return {"ok": True}

# --- Student Manual Enrolment & Bulk Import ---

@app.post("/admin/enroll")
@app.post("/admin/students/enroll")
async def manual_enroll(b: ManualEnroll, _=Depends(admin)):
    target_course = await find_course(b.course_id)
    if not target_course:
        raise HTTPException(404, "Course not found.")
    
    u = await db.users.find_one({"email": b.email.lower().strip()})
    temp_password = None
    if not u:
        temp_password = secrets.token_urlsafe(8)
        r = await db.users.insert_one({
            "email": b.email.lower().strip(),
            "name": b.name.strip(),
            "phone": b.phone.strip(),
            "password": pwd.hash(temp_password),
            "role": "student",
            "created": datetime.utcnow().isoformat()
        })
        uid = r.inserted_id
    else:
        uid = u["_id"]
    
    await db.enrollments.update_one(
        {"user": uid, "course": target_course["_id"]},
        {"$setOnInsert": {
            "completed": [],
            "score": None,
            "certificate": None,
            "attempts": [],
            "enrolled_at": datetime.utcnow().isoformat()
        }},
        upsert=True
    )
    
    if temp_password:
        await send_email(
            b.email,
            f"You have been enrolled in {target_course['title']} - O2 Campus",
            f"<p>Hello {b.name},</p><p>You have been enrolled in <b>{target_course['title']}</b> by the administrator.</p><p>Your login email is: <b>{b.email}</b><br/>Your temporary password is: <b>{temp_password}</b></p><p>Log in at <a href='http://localhost:3000/learn/login'>http://localhost:3000/learn/login</a></p>",
            "manual_enrollment"
        )
    
    return {"ok": True, "temp_password": temp_password, "user_id": str(uid)}

@app.post("/admin/bulk-enroll")
@app.post("/admin/students/bulk-import")
async def bulk_import(b: BulkImport, _=Depends(admin)):
    results = []
    for s in b.students:
        target_course = await find_course(s.course_id)
        if not target_course:
            results.append({"email": s.email, "status": "error", "message": f"Course '{s.course_id}' not found"})
            continue
        
        u = await db.users.find_one({"email": s.email.lower().strip()})
        temp_password = None
        if not u:
            temp_password = secrets.token_urlsafe(8)
            r = await db.users.insert_one({
                "email": s.email.lower().strip(),
                "name": s.name.strip(),
                "phone": s.phone.strip() if s.phone else "",
                "password": pwd.hash(temp_password),
                "role": "student",
                "created": datetime.utcnow().isoformat()
            })
            uid = r.inserted_id
        else:
            uid = u["_id"]
        
        await db.enrollments.update_one(
            {"user": uid, "course": target_course["_id"]},
            {"$setOnInsert": {
                "completed": [],
                "score": None,
                "certificate": None,
                "attempts": [],
                "enrolled_at": datetime.utcnow().isoformat()
            }},
            upsert=True
        )
        
        if temp_password:
            await send_email(
                s.email,
                f"Your O2 Campus Account for {target_course['title']}",
                f"<p>Hello {s.name},</p><p>Welcome to O2 Campus! You have been enrolled in <b>{target_course['title']}</b>.</p><p>Email: {s.email}<br/>Temporary Password: <b>{temp_password}</b></p><p>Sign in: <a href='http://localhost:3000/learn/login'>http://localhost:3000/learn/login</a></p>",
                "bulk_import"
            )
        
        results.append({
            "name": s.name,
            "email": s.email,
            "course": target_course["title"],
            "temp_password": temp_password,
            "status": "success"
        })
        
    success_count = len([r for r in results if r["status"] == "success"])
    return {"count": success_count, "imported": success_count, "details": results}

@app.get("/admin/students")
async def admin_students(search: Optional[str] = None, course: Optional[str] = None, _=Depends(admin)):
    query = {"role": "student"}
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}}
        ]
    
    students = []
    async for u in db.users.find(query).sort("created", -1):
        # Fetch their enrollments
        u_enrolls = []
        async for e in db.enrollments.find({"user": u["_id"]}):
            c = await db.courses.find_one({"_id": e["course"]})
            if c:
                lessons_len = max(len(c.get("lessons", [])), 1)
                u_enrolls.append({
                    "course_id": str(c["_id"]),
                    "course_title": c["title"],
                    "progress": round(100 * len(e.get("completed", [])) / lessons_len),
                    "score": e.get("score"),
                    "certified": bool(e.get("certificate")),
                    "certificate_code": e.get("certificate", {}).get("code") if e.get("certificate") else None,
                    "enrolled_at": e.get("enrolled_at")
                })
        
        if course and course != "all":
            if not any(en["course_id"] == course or en["course_title"] == course for en in u_enrolls):
                continue

        students.append({
            "id": str(u["_id"]),
            "name": u.get("name", "Unnamed"),
            "email": u["email"],
            "phone": u.get("phone", ""),
            "created": u.get("created", ""),
            "enrollments": u_enrolls
        })
    return students

@app.post("/admin/students/{id}/reset-password")
async def admin_reset_student_password(id: str, _=Depends(admin)):
    u = await db.users.find_one({"_id": oid(id)})
    if not u:
        raise HTTPException(404, "Student not found.")
    temp = secrets.token_urlsafe(8)
    await db.users.update_one({"_id": u["_id"]}, {"$set": {"password": pwd.hash(temp)}})
    await send_email(
        u["email"],
        "Your O2 Campus Password Has Been Reset",
        f"<p>Hello {u.get('name', 'Learner')},</p><p>An administrator has reset your password.</p><p>Your new temporary password is: <b>{temp}</b></p><p>Log in at <a href='http://localhost:3000/learn/login'>http://localhost:3000/learn/login</a></p>",
        "admin_password_reset"
    )
    return {"ok": True, "temp_password": temp, "email": u["email"]}

@app.delete("/admin/enrollments/{user_id}/{course_id}")
async def unenroll_student(user_id: str, course_id: str, _=Depends(admin)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    await db.enrollments.delete_one({"user": oid(user_id), "course": c["_id"]})
    return {"ok": True}

# --- Course Admin Management ---

@app.get("/admin/courses")
async def admin_courses(_=Depends(admin)):
    return [out(c) async for c in db.courses.find()]

@app.post("/admin/courses")
async def create_course(c: Course, _=Depends(admin)):
    data = c.model_dump()
    if not data.get("slug"):
        data["slug"] = re.sub(r'[^a-z0-9]+', '-', data["title"].lower()).strip('-')
    r = await db.courses.insert_one(data)
    return {"id": str(r.inserted_id), "slug": data["slug"]}

@app.put("/admin/courses/{id}")
async def edit_course(id: str, c: Course, _=Depends(admin)):
    data = c.model_dump()
    if not data.get("slug"):
        data["slug"] = re.sub(r'[^a-z0-9]+', '-', data["title"].lower()).strip('-')
    await db.courses.replace_one({"_id": oid(id)}, data)
    return {"ok": True}

@app.delete("/admin/courses/{id}")
async def del_course(id: str, _=Depends(admin)):
    await db.courses.delete_one({"_id": oid(id)})
    return {"ok": True}

# --- Student Learning Experience ---

@app.get("/learn/courses")
async def my_courses(u=Depends(user)):
    res = []
    async for e in db.enrollments.find({"user": u["_id"]}):
        c = await db.courses.find_one({"_id": e["course"]})
        if not c:
            continue
        total = max(len(c.get("lessons", [])), 1)
        completed = e.get("completed", [])
        res.append({
            "course": out(c) | {"quiz": []},
            "progress": round(100 * len(completed) / total),
            "completed": completed,
            "score": e.get("score"),
            "certificate": e.get("certificate"),
            "attempts": len(e.get("attempts", []))
        })
    return res

@app.get("/learn/course/{cid}")
async def learn_course(cid: str, u=Depends(user)):
    c = await find_course(cid)
    if not c:
        raise HTTPException(404, "Course not found.")
    cid_obj = c.get("_id")
    cid_str = str(cid_obj or c.get("id"))
    
    e = await db.enrollments.find_one({
        "user": u["_id"],
        "$or": [{"course": cid_obj}, {"course": cid_str}]
    })
    if not e and u.get("role") != "admin":
        raise HTTPException(403, "You are not enrolled in this course.")
    
    # Calculate stats
    c_out = out(c)
    quiz_bank = c_out.get("quiz", [])
    c_out["quiz_size"] = len(quiz_bank)
    c_out["quiz"] = [] # Don't send quiz answers to student here
    if "lessons" not in c_out:
        c_out["lessons"] = []
    
    rv = [out(r) async for r in db.ratings.find({"course": cid_str})]
    avg = round(sum(r.get("stars", 5) for r in rv) / len(rv), 1) if rv else None
    
    completed = e.get("completed", []) if e else []
    score = e.get("score") if e else None
    certificate = e.get("certificate") if e else None
    attempts = e.get("attempts", []) if e else []
    
    return {
        "course": c_out,
        "completed": completed,
        "score": score,
        "certificate": certificate,
        "attempts": attempts,
        "reviews": rv,
        "rating": avg
    }

@app.post("/learn/{course_id}/lessons/{idx}/complete")
async def complete_lesson(course_id: str, idx: int, u=Depends(user)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    await db.enrollments.update_one(
        {"user": u["_id"], "course": c["_id"]},
        {"$addToSet": {"completed": idx}}
    )
    return {"ok": True, "lesson": idx}

@app.post("/learn/{course_id}/lessons/{idx}/uncomplete")
async def uncomplete_lesson(course_id: str, idx: int, u=Depends(user)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    await db.enrollments.update_one(
        {"user": u["_id"], "course": c["_id"]},
        {"$pull": {"completed": idx}}
    )
    return {"ok": True, "lesson": idx}

# --- In-Lesson Quiz ---

@app.post("/learn/{course_id}/lessons/{idx}/quiz")
async def submit_lesson_quiz(course_id: str, idx: int, b: LessonQuizAnswer, u=Depends(user)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    lessons = c.get("lessons", [])
    if idx < 0 or idx >= len(lessons):
        raise HTTPException(404, "Lesson not found.")
    l = lessons[idx]
    quiz_questions = l.get("quiz", [])
    if not quiz_questions:
        return {"score": 100, "passed": True, "feedback": "Lesson completed without quiz questions."}
    
    correct_count = 0
    feedback = []
    for i, q in enumerate(quiz_questions):
        user_ans = b.answers[i] if i < len(b.answers) else -1
        is_right = (user_ans == q.get("answer"))
        if is_right:
            correct_count += 1
        feedback.append({
            "question": q["q"],
            "correct": is_right,
            "correct_answer": q.get("answer"),
            "explanation": q.get("explanation", "")
        })
    
    score = round(100 * correct_count / max(len(quiz_questions), 1))
    passed = score >= 60
    
    if passed:
        await db.enrollments.update_one(
            {"user": u["_id"], "course": c["_id"]},
            {"$addToSet": {"completed": idx}}
        )
    
    return {"score": score, "passed": passed, "feedback": feedback}

# --- Timed Final Test, Question Banks, Attempt Limits & Randomised Questions ---

@app.get("/learn/{course_id}/quiz")
async def get_test(course_id: str, u=Depends(user)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    e = await db.enrollments.find_one({"user": u["_id"], "course": c["_id"]})
    if not e and u.get("role") != "admin":
        raise HTTPException(403, "You are not enrolled in this course.")

    lesson_count = len(c.get("lessons", []))
    completed = set(e.get("completed", [])) if e else set()
    if u.get("role") != "admin" and any(i not in completed for i in range(lesson_count)):
        raise HTTPException(403, "Complete all course lessons before taking the final test.")
    
    attempts = e.get("attempts", []) if e else []
    attempt_limit = c.get("attempt_limit", 3)
    attempts_used = len(attempts)
    attempts_left = max(0, attempt_limit - attempts_used)
    
    bank = c.get("quiz", [])
    if not bank:
        raise HTTPException(400, "No final test questions configured for this course yet.")
    
    # Check if attempts exceeded
    if attempts_left <= 0 and not (e and e.get("certificate")):
        raise HTTPException(400, f"You have reached the maximum attempt limit ({attempt_limit} attempts) for this test.")
    
    sample_size = c.get("quiz_bank_sample_size") or len(bank)
    sample_size = min(sample_size, len(bank))
    
    # Pick random indices from question bank
    all_indices = list(range(len(bank)))
    random.shuffle(all_indices)
    chosen_indices = all_indices[:sample_size]
    
    # Issue session token with chosen indices
    time_limit = c.get("time_limit_minutes", 20)
    session_token = jwt.encode(
        {
            "sub": str(u["_id"]),
            "cid": str(c["_id"]),
            "indices": chosen_indices,
            "exp": time.time() + (time_limit + 10) * 60
        },
        SECRET,
        algorithm="HS256"
    )
    
    questions = []
    for i in chosen_indices:
        q = bank[i]
        questions.append({"q": q["q"], "options": q["options"]})
        
    return {
        "course_title": c["title"],
        "pass_mark": c.get("pass_mark", 70),
        "time_limit_minutes": time_limit,
        "attempt_limit": attempt_limit,
        "attempts_used": attempts_used,
        "attempts_left": attempts_left,
        "highest_score": e.get("score") if e else None,
        "passed": bool(e.get("certificate")) if e else False,
        "questions": questions,
        "session_token": session_token
    }

@app.post("/learn/{course_id}/quiz")
async def submit_test(course_id: str, b: Answers, u=Depends(user)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    e = await db.enrollments.find_one({"user": u["_id"], "course": c["_id"]})
    if not e and u.get("role") != "admin":
        raise HTTPException(403, "You are not enrolled in this course.")

    lesson_count = len(c.get("lessons", []))
    completed = set(e.get("completed", [])) if e else set()
    if u.get("role") != "admin" and any(i not in completed for i in range(lesson_count)):
        raise HTTPException(403, "Complete all course lessons before taking the final test.")
    
    bank = c.get("quiz", [])
    if not bank:
        raise HTTPException(400, "No quiz configured.")
    
    # Verify session token to match the exact randomised question set
    if b.session_token:
        try:
            payload = jwt.decode(b.session_token, SECRET, algorithms=["HS256"])
            indices = payload.get("indices", list(range(len(bank))))
        except Exception:
            indices = list(range(len(bank)))
    else:
        indices = list(range(len(bank)))
    
    selected_questions = [bank[i] for i in indices if i < len(bank)]
    
    # Calculate score
    right = 0
    feedback = []
    for i, q in enumerate(selected_questions):
        user_ans = b.answers[i] if i < len(b.answers) else -1
        is_correct = (user_ans == q.get("answer"))
        if is_correct:
            right += 1
        feedback.append({
            "q": q["q"],
            "correct": is_correct,
            "options": q["options"],
            "selected": user_ans,
            "answer": q.get("answer"),
            "explanation": q.get("explanation", "")
        })
        
    score = round(100 * right / max(len(selected_questions), 1))
    pass_mark = c.get("pass_mark", 70)
    passed = score >= pass_mark
    
    cert = None
    if passed:
        cert_code = "O2-" + secrets.token_hex(4).upper()
        cert = {
            "code": cert_code,
            "issued": datetime.utcnow().isoformat(),
            "name": u.get("name", "Student"),
            "course": c["title"],
            "score": score
        }
        # Send congratulatory email
        await send_email(
            u["email"],
            f"Congratulations! You Earned Your Certificate in {c['title']}",
            f"""
            <div style="font-family:sans-serif;color:#0a0e2a;">
                <h2 style="color:#010f6b;">Congratulations, {u.get('name', 'Learner')}!</h2>
                <p>You have successfully passed the final exam for <b>{c['title']}</b> with a score of <b>{score}%</b> (Pass mark: {pass_mark}%).</p>
                <p>Your official Certificate Verification Code is: <b style="color:#ff8c1e;font-size:18px;">{cert_code}</b></p>
                <p>You can view, print, or download your verified certificate anytime at <a href="http://localhost:3000/verify/{cert_code}">http://localhost:3000/verify/{cert_code}</a> or in your student portal.</p>
            </div>
            """,
            "certificate_awarded"
        )
    
    attempt_record = {
        "date": datetime.utcnow().isoformat(),
        "score": score,
        "passed": passed
    }
    
    if e:
        existing_cert = e.get("certificate")
        existing_score = e.get("score")
        highest_score = max(score, existing_score if existing_score is not None else 0)
        
        await db.enrollments.update_one(
            {"_id": e["_id"]},
            {
                "$set": {
                    "score": highest_score,
                    "certificate": cert or existing_cert
                },
                "$push": {"attempts": attempt_record}
            }
        )
    
    return {
        "score": score,
        "passed": passed,
        "pass_mark": pass_mark,
        "certificate": cert or (e.get("certificate") if e else None),
        "feedback": feedback
    }

# --- Certificates & Verification ---

@app.get("/learn/certificates")
async def student_certificates(u=Depends(user)):
    certs = []
    async for e in db.enrollments.find({"user": u["_id"], "certificate": {"$ne": None}}):
        certs.append(e["certificate"])
    return certs

@app.get("/verify/{code}")
async def verify_cert(code: str):
    e = await db.enrollments.find_one({"certificate.code": code.strip().upper()})
    if not e:
        raise HTTPException(404, "Certificate not found. Please check code.")
    return e["certificate"]

# --- Upcoming Live-Class Calendar & Reminders ---

@app.get("/learn/schedule")
async def live_schedule(u=Depends(user)):
    res = []
    async for e in db.enrollments.find({"user": u["_id"]}):
        c = await db.courses.find_one({"_id": e["course"]})
        if not c:
            continue
        for i, l in enumerate(c.get("lessons", [])):
            if l.get("kind") == "live" and l.get("starts_at"):
                res.append({
                    "course": c["title"],
                    "course_id": str(c["_id"]),
                    "course_slug": c.get("slug"),
                    "idx": i,
                    "title": l["title"],
                    "url": l.get("url", ""),
                    "starts_at": l["starts_at"],
                    "instructor": c.get("instructor", "O2 Lab Instructor"),
                    "description": l.get("description", "")
                })
    return sorted(res, key=lambda x: str(x["starts_at"]))

@app.post("/admin/live-classes/remind")
async def admin_remind_live_class(course_id: str, lesson_idx: int, _=Depends(admin)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    lessons = c.get("lessons", [])
    if lesson_idx < 0 or lesson_idx >= len(lessons):
        raise HTTPException(404, "Lesson not found.")
    l = lessons[lesson_idx]
    
    # Get all enrolled students
    students = []
    async for e in db.enrollments.find({"course": c["_id"]}):
        u = await db.users.find_one({"_id": e["user"]})
        if u and u.get("email"):
            students.append(u)
    
    count = 0
    for s in students:
        body = f"""
        <div style="font-family:sans-serif;line-height:1.6;color:#0a0e2a;">
            <h2 style="color:#010f6b;">Live Class Reminder: {l['title']}</h2>
            <p>Hello <b>{s.get('name', 'Learner')}</b>,</p>
            <p>This is a reminder for your upcoming live class in <b>{c['title']}</b>.</p>
            <div style="background:#f6f7fb;padding:16px;border-radius:12px;margin:16px 0;border:1px solid #e0e4f0;">
                <p style="margin:4px 0;"><b>Topic:</b> {l['title']}</p>
                <p style="margin:4px 0;"><b>Start Time:</b> {l.get('starts_at', 'Scheduled today')}</p>
                <p style="margin:4px 0;"><b>Instructor:</b> {c.get('instructor', 'O2 Instructor')}</p>
                <p style="margin:12px 0 4px 0;">
                    <a href="{l.get('url')}" style="background:#ff8c1e;color:#0a0e2a;padding:10px 20px;text-decoration:none;border-radius:24px;font-weight:bold;display:inline-block;">Join Live on Google Meet</a>
                </p>
            </div>
            <p>See you in class!</p>
        </div>
        """
        await send_email(s["email"], f"Live Class Reminder: {l['title']} - {c['title']}", body, "live_reminder")
        count += 1
        
    return {"ok": True, "sent_to_count": count}

# --- Assignments with File Upload & Instructor Grading ---

@app.post("/learn/{course_id}/lessons/{idx}/assignment")
async def submit_assignment(course_id: str, idx: int, b: AssignmentSubmit, u=Depends(user)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    lessons = c.get("lessons", [])
    if idx < 0 or idx >= len(lessons):
        raise HTTPException(404, "Lesson not found.")
    l = lessons[idx]
    
    doc = {
        "course_id": str(c["_id"]),
        "course_title": c["title"],
        "lesson_idx": idx,
        "lesson_title": l["title"],
        "user_id": str(u["_id"]),
        "student_name": u.get("name", "Student"),
        "student_email": u["email"],
        "file_url": b.file_url,
        "notes": b.notes,
        "status": "submitted",
        "submitted_at": datetime.utcnow().isoformat(),
        "grade": None,
        "score": None,
        "feedback": None
    }
    
    await db.assignments.update_one(
        {"user_id": str(u["_id"]), "course_id": str(c["_id"]), "lesson_idx": idx},
        {"$set": doc},
        upsert=True
    )
    return {"ok": True, "message": "Assignment submitted successfully for instructor review."}

@app.get("/learn/{course_id}/lessons/{idx}/assignment")
async def get_my_assignment(course_id: str, idx: int, u=Depends(user)):
    c = await find_course(course_id)
    if not c:
        raise HTTPException(404, "Course not found.")
    a = await db.assignments.find_one({
        "user_id": str(u["_id"]),
        "course_id": str(c["_id"]),
        "lesson_idx": idx
    })
    return out(a) if a else None

@app.get("/admin/assignments")
async def admin_assignments(status: Optional[str] = None, _=Depends(admin)):
    query = {"status": status} if status and status != "all" else {}
    return [out(a) async for a in db.assignments.find(query).sort("submitted_at", -1)]

@app.post("/admin/assignments/{id}/grade")
async def grade_assignment(id: str, b: AssignmentGrade, _=Depends(admin)):
    a = await db.assignments.find_one({"_id": oid(id)})
    if not a:
        raise HTTPException(404, "Assignment submission not found.")
    
    await db.assignments.update_one(
        {"_id": a["_id"]},
        {"$set": {
            "status": "graded",
            "grade": b.grade,
            "score": b.score,
            "feedback": b.feedback,
            "graded_at": datetime.utcnow().isoformat()
        }}
    )
    
    # Notify student by email
    await send_email(
        a["student_email"],
        f"Your Assignment for {a['lesson_title']} Was Graded",
        f"""
        <div style="font-family:sans-serif;color:#0a0e2a;">
            <h2 style="color:#010f6b;">Assignment Feedback Available</h2>
            <p>Hello <b>{a['student_name']}</b>,</p>
            <p>Your instructor has graded your assignment for <b>{a['lesson_title']}</b> ({a['course_title']}).</p>
            <div style="background:#f6f7fb;padding:16px;border-radius:8px;border:1px solid #ddd;margin:16px 0;">
                <p><b>Grade:</b> {b.grade} ({b.score}/100)</p>
                <p><b>Instructor Feedback:</b> {b.feedback}</p>
            </div>
            <p>View your lesson to review feedback: <a href="http://localhost:3000/learn/courses/{a['course_id']}/play?l={a['lesson_idx']}">Go to Lesson</a></p>
        </div>
        """,
        "assignment_graded"
    )
    return {"ok": True}

# --- Announcements ---

@app.post("/admin/announcements")
async def create_announcement(b: AnnouncementCreate, u=Depends(admin)):
    doc = {
        "title": b.title,
        "text": b.text,
        "course": b.course,
        "priority": b.priority,
        "author": u.get("name", "Instructor"),
        "created": datetime.utcnow().isoformat()
    }
    r = await db.announcements.insert_one(doc)
    return {"id": str(r.inserted_id), "ok": True}

@app.get("/admin/announcements")
async def admin_announcements(_=Depends(admin)):
    return [out(a) async for a in db.announcements.find().sort("created", -1)]

@app.delete("/admin/announcements/{id}")
async def delete_announcement(id: str, _=Depends(admin)):
    await db.announcements.delete_one({"_id": oid(id)})
    return {"ok": True}

@app.get("/learn/announcements")
async def student_announcements(course_id: Optional[str] = None, u=Depends(user)):
    # Get all courses user is enrolled in
    enrolled_courses = []
    async for e in db.enrollments.find({"user": u["_id"]}):
        enrolled_courses.append(str(e["course"]))
    
    query = {"$or": [
        {"course": "all"},
        {"course": {"$in": enrolled_courses}}
    ]}
    if course_id:
        query = {"$or": [{"course": "all"}, {"course": course_id}]}
    
    return [out(a) async for a in db.announcements.find(query).sort("created", -1).limit(20)]

# --- Discussion Forum ---

@app.get("/learn/{cid}/discussion")
async def get_discussion(cid: str, lesson: Optional[int] = None, u=Depends(user)):
    c = await find_course(cid)
    if not c:
        raise HTTPException(404, "Course not found.")
    query = {"course": str(c["_id"])}
    if lesson is not None:
        query["lesson"] = lesson
    return [out(p) async for p in db.posts.find(query).sort("created", -1).limit(80)]

@app.post("/learn/{cid}/discussion")
async def post_discussion(cid: str, b: Post, u=Depends(user)):
    c = await find_course(cid)
    if not c:
        raise HTTPException(404, "Course not found.")
    is_admin = u.get("role") == "admin"
    doc = {
        "course": str(c["_id"]),
        "name": u.get("name", "Anonymous"),
        "role": u.get("role", "student"),
        "is_instructor": is_admin,
        "text": b.text[:2000],
        "lesson": b.lesson,
        "created": datetime.utcnow().isoformat()
    }
    await db.posts.insert_one(doc)
    return {"ok": True}

# --- Ratings & Reviews ---

@app.post("/learn/{cid}/rate")
async def rate_course(cid: str, b: Rate, u=Depends(user)):
    c = await find_course(cid)
    if not c:
        raise HTTPException(404, "Course not found.")
    if not 1 <= b.stars <= 5:
        raise HTTPException(400, "Choose 1 to 5 stars.")
    await db.ratings.update_one(
        {"course": str(c["_id"]), "user": str(u["_id"])},
        {"$set": {
            "stars": b.stars,
            "comment": b.comment[:800],
            "name": u.get("name", "Learner"),
            "created": datetime.utcnow().isoformat()
        }},
        upsert=True
    )
    return {"ok": True}

# --- Admin Analytics ---

@app.get("/admin/analytics")
async def get_analytics(_=Depends(admin)):
    total_students = await db.users.count_documents({"role": "student"})
    total_courses = await db.courses.count_documents({})
    total_apps = await db.applications.count_documents({})
    pending_apps = await db.applications.count_documents({"status": "pending"})
    certs_issued = await db.enrollments.count_documents({"certificate": {"$ne": None}})
    
    # Calculate revenue & course stats
    course_stats = []
    total_revenue = 0
    total_progress_sum = 0
    total_enrollments_count = 0
    drop_off_count = 0
    
    async for c in db.courses.find():
        cid = c["_id"]
        enrolls = [e async for e in db.enrollments.find({"course": cid})]
        count = len(enrolls)
        lessons_len = max(len(c.get("lessons", [])), 1)
        
        c_progress_sum = 0
        c_drop_offs = 0
        c_certified = 0
        
        for e in enrolls:
            completed_len = len(e.get("completed", []))
            prog = round(100 * completed_len / lessons_len)
            c_progress_sum += prog
            if prog < 30 and completed_len > 0:
                c_drop_offs += 1
            if e.get("certificate"):
                c_certified += 1
                
        avg_progress = round(c_progress_sum / count) if count else 0
        drop_off_rate = round(100 * c_drop_offs / count) if count else 0
        c_revenue = count * c.get("price", 0)
        total_revenue += c_revenue
        total_progress_sum += c_progress_sum
        total_enrollments_count += count
        drop_off_count += c_drop_offs
        
        course_stats.append({
            "id": str(c["_id"]),
            "slug": c.get("slug"),
            "title": c["title"],
            "price": c.get("price", 0),
            "students": count,
            "revenue": c_revenue,
            "avg_progress": avg_progress,
            "drop_off_rate": drop_off_rate,
            "certified": c_certified
        })
        
    overall_completion_rate = round(total_progress_sum / total_enrollments_count) if total_enrollments_count else 0
    overall_drop_off_rate = round(100 * drop_off_count / total_enrollments_count) if total_enrollments_count else 0
    
    # Recent activity
    recent_activity = []
    async for e in db.enrollments.find().sort("_id", -1).limit(6):
        u = await db.users.find_one({"_id": e["user"]})
        c = await db.courses.find_one({"_id": e["course"]})
        if u and c:
            recent_activity.append({
                "type": "enrollment",
                "student": u.get("name", "Student"),
                "course": c["title"],
                "certified": bool(e.get("certificate")),
                "score": e.get("score")
            })
            
    return {
        "active_students": total_students,
        "total_courses": total_courses,
        "total_revenue": total_revenue,
        "completion_rate": overall_completion_rate,
        "drop_off_rate": overall_drop_off_rate,
        "certificates_issued": certs_issued,
        "pending_applications": pending_apps,
        "total_applications": total_apps,
        "course_stats": course_stats,
        "recent_activity": recent_activity
    }

@app.get("/admin/emails")
async def get_emails(_=Depends(admin)):
    return [out(e) async for e in db.emails.find().sort("sent_at", -1).limit(50)]

@app.get("/admin/overview")
async def overview(_=Depends(admin)):
    return {
        "students": await db.users.count_documents({"role": "student"}),
        "courses": await db.courses.count_documents({}),
        "pending": await db.applications.count_documents({"status": "pending"}),
        "certificates": await db.enrollments.count_documents({"certificate": {"$ne": None}}),
        "assignments": await db.assignments.count_documents({"status": "submitted"}),
        "announcements": await db.announcements.count_documents({})
    }

@app.get("/admin/enrollments")
async def enrollments(_=Depends(admin)):
    res = []
    async for e in db.enrollments.find():
        u = await db.users.find_one({"_id": e["user"]})
        c = await db.courses.find_one({"_id": e["course"]})
        if u and c:
            res.append({
                "user_id": str(u["_id"]),
                "name": u.get("name", "Unnamed"),
                "email": u["email"],
                "course": c["title"],
                "course_id": str(c["_id"]),
                "progress": round(100 * len(e.get("completed", [])) / max(len(c.get("lessons", [])), 1)),
                "score": e.get("score"),
                "certified": bool(e.get("certificate")),
                "attempts": len(e.get("attempts", []))
            })
    return res

@app.get("/admin/upload-signature")
async def sign(_=Depends(admin)):
    import cloudinary, cloudinary.utils
    ts = int(time.time())
    cfg = cloudinary.config()
    return {
        "timestamp": ts,
        "signature": cloudinary.utils.api_sign_request({"timestamp": ts}, cfg.api_secret),
        "api_key": cfg.api_key,
        "cloud_name": cfg.cloud_name
    }

# --- Startup Seeding ---

@app.on_event("startup")
async def seed():
    # Admin seed
    if not await db.users.find_one({"role": "admin"}):
        admin_pass = os.getenv("ADMIN_PASSWORD", "ChangeMe123")
        await db.users.insert_one({
            "email": "admin@o2lab.ng",
            "name": "O2 Lead Instructor (Admin)",
            "role": "admin",
            "password": pwd.hash(admin_pass),
            "phone": "+234 800 000 0000",
            "bio": "Lead Instructor and Program Director at O2 Innovations Lab.",
            "created": datetime.utcnow().isoformat()
        })
    
    # Ensure existing courses have sample rich data (lessons with YouTube/Cloudinary URLs, live Google Meet sessions, in-lesson quizzes, final question bank)
    default_courses = [
        ("cyber-security", "Cyber Security", 100000, "Intermediate"),
        ("data-science", "Data Science and ML", 100000, "Advanced"),
        ("data-analysis", "Data Analysis", 40000, "Beginner"),
        ("mobile-development", "Mobile Development", 50000, "Intermediate"),
        ("vibe-coding", "Vibe Coding", 40000, "Beginner"),
        ("software-development", "Software Development", 50000, "Beginner"),
        ("graphic-design", "Graphic Design", 30000, "Beginner")
    ]
    
    for slug, title, price, level in default_courses:
        existing = await db.courses.find_one({"slug": slug})
        if not existing:
            sample_lessons = [
                {
                    "module": "Module 1: Foundations",
                    "title": f"Introduction to {title}",
                    "kind": "recorded",
                    "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                    "minutes": 35,
                    "description": f"Master the core terminology, principles, and tooling essential for modern {title}.",
                    "resources": ["https://o2lab.ng/syllabus.pdf", "https://github.com/o2lab"],
                    "assignment": f"Write a 1-page summary and tool setup checklist for {title}.",
                    "quiz": [
                        {
                            "q": f"What is the primary objective of this introductory {title} module?",
                            "options": ["Build fundamental domain knowledge", "Skip hands-on practice", "Ignore industry standards", "None of the above"],
                            "answer": 0,
                            "explanation": "Foundations build the core mental model and hands-on tool setup needed for advanced topics."
                        },
                        {
                            "q": "Which best practice should be followed from day one?",
                            "options": ["Documenting your code and workflows", "Working without version control", "Ignoring security guidelines", "Skipping tests"],
                            "answer": 0,
                            "explanation": "Consistent documentation and version control ensure scalable project growth."
                        }
                    ]
                },
                {
                    "module": "Module 1: Foundations",
                    "title": f"Live Masterclass & Q&A: {title} in Practice",
                    "kind": "live",
                    "url": "https://meet.google.com/abc-defg-hij",
                    "starts_at": (datetime.utcnow() + timedelta(days=2, hours=4)).isoformat(),
                    "minutes": 60,
                    "description": "Interactive Google Meet session with your lead instructor to review key concepts, walk through live demos, and answer questions.",
                    "resources": ["https://meet.google.com/abc-defg-hij"],
                    "assignment": "Submit your questions ahead of time or upload your completed exercise worksheet.",
                    "quiz": []
                },
                {
                    "module": "Module 2: Practical Projects",
                    "title": f"Building Real-World {title} Solutions",
                    "kind": "recorded",
                    "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                    "minutes": 45,
                    "description": "Step-by-step walkthrough implementing industry-standard architectures and workflows.",
                    "resources": ["https://github.com/o2lab/exercises"],
                    "assignment": "Submit your GitHub repository link or project archive file for instructor grading.",
                    "quiz": [
                        {
                            "q": "What is the key criterion for a production-ready solution?",
                            "options": ["Reliability, maintainability and security", "Speed of writing with no validation", "Hardcoding all configurations", "Leaving out error handling"],
                            "answer": 0,
                            "explanation": "Production solutions require fault-tolerance, clear architecture, and security."
                        }
                    ]
                }
            ]
            
            sample_quiz_bank = [
                {
                    "q": f"What is the core principle behind scalable {title}?",
                    "options": ["Modular architecture and continuous testing", "Monolithic non-standard components", "Skipping security audits", "Avoiding documentation"],
                    "answer": 0,
                    "explanation": "Modularity and rigorous testing ensure systems remain resilient and maintainable."
                },
                {
                    "q": "How should errors and edge cases be handled?",
                    "options": ["Explicit error handling and structured logging", "Silently ignoring exceptions", "Crashing the host application", "Hiding error messages completely"],
                    "answer": 0,
                    "explanation": "Structured logging and graceful error propagation allow fast troubleshooting."
                },
                {
                    "q": "What role does continuous collaboration play in technical projects?",
                    "options": ["Improves code quality and knowledge sharing", "Slows down progress unnecessarily", "Should be avoided in agile teams", "Only matters for sales teams"],
                    "answer": 0,
                    "explanation": "Pair programming and peer review consistently yield higher reliability."
                },
                {
                    "q": "Which testing methodology should be prioritized before deploying to production?",
                    "options": ["End-to-end and integration testing", "No testing at all", "Testing only on localhost without fixtures", "Manual visual checking once"],
                    "answer": 0,
                    "explanation": "Comprehensive integration and automated tests prevent breaking regressions."
                }
            ]
            
            await db.courses.insert_one({
                "slug": slug,
                "title": title,
                "summary": f"Comprehensive {title} professional program by O2 Innovations Lab with live classes and hands-on projects.",
                "price": price,
                "modes": ["onsite", "online"],
                "level": level,
                "instructor": "O2 Lab Instructors",
                "instructor_bio": "Experienced technology leaders and engineers at O2 Innovations Lab.",
                "language": "English",
                "pass_mark": 70,
                "time_limit_minutes": 20,
                "attempt_limit": 3,
                "quiz_bank_sample_size": 3,
                "lessons": sample_lessons,
                "quiz": sample_quiz_bank,
                "what_you_learn": [
                    f"Core foundational principles of {title}",
                    "Real-world project implementation and case studies",
                    "Industry best practices, tooling and deployment",
                    "Preparation for technical interviews and professional certification"
                ],
                "requirements": [
                    "A laptop or smartphone with internet connection",
                    "Commitment of 4-6 hours weekly for lessons and live classes",
                    "Curiosity and willingness to learn hands-on"
                ]
            })
