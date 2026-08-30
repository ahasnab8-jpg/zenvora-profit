import os, sqlite3, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "zenvora.db")
UPLOADS = os.path.join(BASE, "uploads")
os.makedirs(UPLOADS, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED = {"png","jpg","jpeg","webp","pdf"}

PLANS = [
(1,300,60,3600),(2,560,112,6720),(3,1260,252,15120),(4,3200,640,38400),
(5,6760,1352,81120),(6,13100,2620,157200),(7,26500,5300,318000),(8,52500,10500,630000),
(9,105000,21000,1260000),(10,225000,45000,2700000),(11,520000,104000,6240000),(12,1020000,204000,12240000)
]

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    d = sqlite3.connect(DB)
    d.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active',
      balance INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS plans(
      id INTEGER PRIMARY KEY, investment INTEGER NOT NULL, daily INTEGER NOT NULL,
      duration_days INTEGER NOT NULL, displayed_total INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active'
    );
    CREATE TABLE IF NOT EXISTS user_plans(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, plan_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(plan_id) REFERENCES plans(id)
    );
    CREATE TABLE IF NOT EXISTS deposits(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, plan_id INTEGER,
      amount INTEGER NOT NULL, reference TEXT, proof TEXT, status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL, reviewed_at TEXT, reviewed_by INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(plan_id) REFERENCES plans(id)
    );
    CREATE TABLE IF NOT EXISTS withdrawals(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount INTEGER NOT NULL,
      method TEXT NOT NULL, account_ref TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL, reviewed_at TEXT, reviewed_by INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS transactions(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL,
      amount INTEGER NOT NULL, reference TEXT, created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    for p in PLANS:
        d.execute("INSERT OR IGNORE INTO plans VALUES(?,?,?,?,?,'active')", (p[0],p[1],p[2],60,p[3]))
    now=datetime.utcnow().isoformat()
    if not d.execute("SELECT 1 FROM users WHERE email=?",("admin@demo.local",)).fetchone():
        d.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                  ("Administrator","admin@demo.local",generate_password_hash("Admin123!"),"admin",now))
    if not d.execute("SELECT 1 FROM users WHERE email=?",("demo@example.com",)).fetchone():
        d.execute("INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                  ("Demo User","demo@example.com",generate_password_hash("Demo123!"),"user",now))
    d.commit(); d.close()

def login_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if not session.get("uid"): return redirect(url_for("login"))
        return f(*a,**kw)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if session.get("role") != "admin": flash("Admin access required.","error"); return redirect(url_for("dashboard"))
        return f(*a,**kw)
    return wrapper

@app.context_processor
def inject():
    return {"current_user": db().execute("SELECT * FROM users WHERE id=?",(session.get("uid"),)).fetchone() if session.get("uid") else None}

@app.route("/")
def home():
    return render_template("home.html", plans=db().execute("SELECT * FROM plans WHERE status='active'").fetchall())

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower(); pw=request.form.get("password","")
        if not name or not email or len(pw)<8: flash("Enter valid details; password must be at least 8 characters.","error")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
                             (name,email,generate_password_hash(pw),datetime.utcnow().isoformat()))
                db().commit(); flash("Account created. You can now log in.","success"); return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("Email already registered.","error")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=db().execute("SELECT * FROM users WHERE email=?",(request.form.get("email","").lower(),)).fetchone()
        if u and u["status"]=="active" and check_password_hash(u["password_hash"],request.form.get("password","")):
            session.clear(); session["uid"]=u["id"]; session["role"]=u["role"]; return redirect(url_for("admin" if u["role"]=="admin" else "dashboard"))
        flash("Invalid credentials.","error")
    return render_template("auth.html", mode="login")

@app.get("/logout")
def logout():
    session.clear(); return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    uid=session["uid"]
    return render_template("dashboard.html",
      plans=db().execute("SELECT * FROM plans WHERE status='active'").fetchall(),
      deposits=db().execute("SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC",(uid,)).fetchall(),
      withdrawals=db().execute("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC",(uid,)).fetchall(),
      tx=db().execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 30",(uid,)).fetchall(),
      active=db().execute("SELECT up.*,p.investment,p.daily,p.duration_days,p.displayed_total FROM user_plans up JOIN plans p ON p.id=up.plan_id WHERE up.user_id=? ORDER BY up.id DESC",(uid,)).fetchall())

@app.post("/deposit")
@login_required
def deposit():
    uid=session["uid"]; pid=int(request.form.get("plan_id",0)); amount=int(request.form.get("amount",0))
    p=db().execute("SELECT * FROM plans WHERE id=? AND status='active'",(pid,)).fetchone()
    if not p or amount != p["investment"]: flash("Deposit amount must match the selected plan.","error"); return redirect(url_for("dashboard"))
    proof=request.files.get("proof"); saved=None
    if proof and proof.filename:
        ext=proof.filename.rsplit(".",1)[-1].lower()
        if ext not in ALLOWED: flash("Unsupported proof file type.","error"); return redirect(url_for("dashboard"))
        saved=f"{secrets.token_hex(12)}.{ext}"; proof.save(os.path.join(UPLOADS,saved))
    db().execute("INSERT INTO deposits(user_id,plan_id,amount,reference,proof,created_at) VALUES(?,?,?,?,?,?)",
                 (uid,pid,amount,request.form.get("reference","").strip(),saved,datetime.utcnow().isoformat()))
    db().commit(); flash("Deposit request submitted for admin review.","success"); return redirect(url_for("dashboard"))

@app.post("/withdraw")
@login_required
def withdraw():
    uid=session["uid"]; amount=int(request.form.get("amount",0))
    u=db().execute("SELECT balance FROM users WHERE id=?",(uid,)).fetchone()
    if amount<=0 or amount>u["balance"]: flash("Withdrawal amount exceeds the available demo balance.","error"); return redirect(url_for("dashboard"))
    db().execute("INSERT INTO withdrawals(user_id,amount,method,account_ref,created_at) VALUES(?,?,?,?,?)",
                 (uid,amount,request.form.get("method",""),request.form.get("account_ref","").strip(),datetime.utcnow().isoformat()))
    db().commit(); flash("Withdrawal request submitted for admin review.","success"); return redirect(url_for("dashboard"))

@app.post("/plan/<int:pid>/request")
@login_required
def request_plan(pid):
    p=db().execute("SELECT * FROM plans WHERE id=? AND status='active'",(pid,)).fetchone()
    if not p: flash("Plan unavailable.","error")
    else:
        db().execute("INSERT INTO user_plans(user_id,plan_id,created_at) VALUES(?,?,?)",(session["uid"],pid,datetime.utcnow().isoformat()))
        db().commit(); flash("Plan request created; admin must review the deposit separately.","success")
    return redirect(url_for("dashboard"))

@app.route("/admin")
@login_required
@admin_required
def admin():
    d=db()
    return render_template("admin.html",
      users=d.execute("SELECT id,name,email,role,status,balance,created_at FROM users ORDER BY id DESC").fetchall(),
      deposits=d.execute("SELECT dep.*,u.name,u.email,p.id plan_no FROM deposits dep JOIN users u ON u.id=dep.user_id LEFT JOIN plans p ON p.id=dep.plan_id ORDER BY dep.id DESC").fetchall(),
      withdrawals=d.execute("SELECT w.*,u.name,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC").fetchall(),
      plans=d.execute("SELECT * FROM plans ORDER BY id").fetchall())

@app.post("/admin/deposit/<int:did>/<action>")
@admin_required
def review_deposit(did,action):
    d=db(); dep=d.execute("SELECT * FROM deposits WHERE id=?",(did,)).fetchone()
    if not dep or dep["status"]!="pending": flash("Deposit already reviewed or missing.","error"); return redirect(url_for("admin"))
    if action not in {"approve","reject"}: return redirect(url_for("admin"))
    status="approved" if action=="approve" else "rejected"
    d.execute("UPDATE deposits SET status=?,reviewed_at=?,reviewed_by=? WHERE id=?",(status,datetime.utcnow().isoformat(),session["uid"],did))
    if status=="approved":
        d.execute("UPDATE users SET balance=balance+? WHERE id=?",(dep["amount"],dep["user_id"]))
        d.execute("INSERT INTO transactions(user_id,kind,amount,reference,created_at) VALUES(?,?,?,?,?)",(dep["user_id"],"deposit",dep["amount"],dep["reference"],datetime.utcnow().isoformat()))
        # Activate a matching requested plan, if one exists.
        d.execute("UPDATE user_plans SET status='active' WHERE user_id=? AND plan_id=? AND status='pending'",
                  (dep["user_id"],dep["plan_id"]))
    d.commit(); flash(f"Deposit {status}.","success"); return redirect(url_for("admin"))

@app.post("/admin/withdraw/<int:wid>/<action>")
@admin_required
def review_withdrawal(wid,action):
    d=db(); w=d.execute("SELECT * FROM withdrawals WHERE id=?",(wid,)).fetchone()
    if not w or w["status"]!="pending": flash("Withdrawal already reviewed or missing.","error"); return redirect(url_for("admin"))
    if action not in {"approve","reject"}: return redirect(url_for("admin"))
    if action=="approve":
        u=d.execute("SELECT balance FROM users WHERE id=?",(w["user_id"],)).fetchone()
        if u["balance"] < w["amount"]:
            d.execute("UPDATE withdrawals SET status='rejected',reviewed_at=?,reviewed_by=? WHERE id=?",(datetime.utcnow().isoformat(),session["uid"],wid))
            d.commit(); flash("Withdrawal rejected: insufficient balance at review time.","error"); return redirect(url_for("admin"))
        d.execute("UPDATE users SET balance=balance-? WHERE id=?",(w["amount"],w["user_id"]))
        d.execute("INSERT INTO transactions(user_id,kind,amount,reference,created_at) VALUES(?,?,?,?,?)",(w["user_id"],"withdrawal",-w["amount"],w["account_ref"],datetime.utcnow().isoformat()))
        status="approved"
    else: status="rejected"
    d.execute("UPDATE withdrawals SET status=?,reviewed_at=?,reviewed_by=? WHERE id=?",(status,datetime.utcnow().isoformat(),session["uid"],wid))
    d.commit(); flash(f"Withdrawal {status}.","success"); return redirect(url_for("admin"))

@app.post("/admin/user/<int:uid>/status")
@admin_required
def user_status(uid):
    status=request.form.get("status")
    if status not in {"active","suspended"}: return redirect(url_for("admin"))
    db().execute("UPDATE users SET status=? WHERE id=? AND role!='admin'",(status,uid)); db().commit()
    return redirect(url_for("admin"))

@app.post("/admin/plan/<int:pid>/status")
@admin_required
def plan_status(pid):
    status=request.form.get("status")
    if status not in {"active","disabled"}: return redirect(url_for("admin"))
    db().execute("UPDATE plans SET status=? WHERE id=?",(status,pid)); db().commit()
    return redirect(url_for("admin"))

@app.get("/health")
def health(): return {"ok":True}

if __name__=="__main__":
    with app.app_context(): init_db()
    app.run(host="127.0.0.1",port=int(os.environ.get("PORT",5000)),debug=True)
