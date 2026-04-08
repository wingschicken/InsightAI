import json
import os
import time
import uvicorn
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, Form, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash, check_password_hash
from pydantic import BaseModel
from app.models import SessionLocal, User, ScanHistory
from app.scanner import run_nmap
from app.web_checks import discover_web_targets, run_web_checks, build_owasp_mapping
from app.ai_client import analyze_scan_result

app = FastAPI()
templates = Jinja2Templates(directory='app/templates')

PROFILE_OPTIONS = ['fast_recon', 'basic', 'top_ports', 'service', 'full']


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)):
    username = request.cookies.get('username')
    if not username:
        return None
    return db.query(User).filter(User.username == username).first()


def render_template(request: Request, template_name: str, context: dict, user: User | None = None):
    context = {
        'request': request,
        'user': user,
        'theme_class': 'light-mode' if user and user.theme == 'light' else 'dark-mode',
        **context,
    }
    return templates.TemplateResponse(template_name, context)


@app.get('/', response_class=HTMLResponse)
def index(request: Request, user: User | None = Depends(get_current_user)):
    if not user:
        return RedirectResponse('/login')
    return render_template(request, 'index.html', {})


@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request, user: User | None = Depends(get_current_user)):
    if user:
        return RedirectResponse('/scan')
    return render_template(request, 'login.html', {'error': None})


@app.post('/login', response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not check_password_hash(user.password, password):
        return render_template(request, 'login.html', {'error': 'Invalid username or password'})

    response = RedirectResponse('/scan', status_code=302)
    response.set_cookie(key='username', value=username, httponly=True)
    return response


@app.get('/register', response_class=HTMLResponse)
def register_page(request: Request, user: User | None = Depends(get_current_user)):
    if user:
        return RedirectResponse('/scan')
    return render_template(request, 'register.html', {'error': None})


@app.post('/register', response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(''),
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == username).first():
        return render_template(request, 'register.html', {'error': 'Username already exists'})

    hashed_password = generate_password_hash(password)
    user = User(
        username=username,
        password=hashed_password,
        email=email,
        display_name=username,
        theme='dark',
        preferred_profile='basic',
        default_use_ai=True,
    )
    db.add(user)
    db.commit()
    return RedirectResponse('/login', status_code=302)


@app.get('/logout')
def logout():
    response = RedirectResponse('/login', status_code=302)
    response.delete_cookie('username')
    return response


@app.get('/scan', response_class=HTMLResponse)
def scan_page(request: Request, user: User | None = Depends(get_current_user)):
    if not user:
        return RedirectResponse('/login')

    return render_template(request, 'scan.html', {
        'target': '',
        'profile': user.preferred_profile or 'basic',
        'web_scan': True,
        'use_ai': user.default_use_ai,
        'result': None,
        'error': None,
        'profile_options': PROFILE_OPTIONS,
    }, user=user)


@app.post('/scan', response_class=HTMLResponse)
def scan_submit(
    request: Request,
    target: str = Form(...),
    profile: str = Form('basic'),
    web_scan: str | None = Form(None),
    use_ai: str | None = Form(None),
    user: User | None = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse('/login')

    if not target:
        return render_template(request, 'scan.html', {
            'target': target,
            'profile': profile,
            'web_scan': bool(web_scan),
            'use_ai': bool(use_ai),
            'result': None,
            'error': 'Target is required',
            'profile_options': PROFILE_OPTIONS,
        }, user=user)

    start_time = time.time()
    
    nmap_result = run_nmap(target, profile)
    web_checks = {'performed': False, 'findings': [], 'urls': []}
    owasp_mapping = []
    if web_scan:
        web_targets = discover_web_targets(target, nmap_result)
        if web_targets:
            web_checks = run_web_checks(web_targets)
            owasp_mapping = build_owasp_mapping(web_checks.get('findings', []))

    scan_report = {
        'target': target,
        'network_scan': nmap_result,
        'web_checks': web_checks,
        'owasp_mapping': owasp_mapping,
    }

    ai_analysis = analyze_scan_result(scan_report) if use_ai else {}
    
    duration = int(time.time() - start_time)

    result = {
        'target': target,
        'network_scan': nmap_result,
        'web_checks': web_checks,
        'owasp_mapping': owasp_mapping,
        'ai_analysis': ai_analysis,
    }

    history_item = ScanHistory(
        user_id=user.id,
        target=target,
        profile=profile,
        web_scan=bool(web_scan),
        use_ai=bool(use_ai),
        result=json.dumps(result),
        duration=duration
    )
    db.add(history_item)
    db.commit()

    return render_template(request, 'scan.html', {
        'target': target,
        'profile': profile,
        'web_scan': bool(web_scan),
        'use_ai': bool(use_ai),
        'result': result,
        'duration': duration,
        'error': None,
        'profile_options': PROFILE_OPTIONS,
    }, user=user)


@app.get('/profile', response_class=HTMLResponse)
def profile_page(request: Request, user: User | None = Depends(get_current_user)):
    if not user:
        return RedirectResponse('/login')

    return render_template(request, 'profile.html', {
        'error': None,
        'profile_options': PROFILE_OPTIONS,
    }, user=user)


@app.post('/profile', response_class=HTMLResponse)
def profile_update(
    request: Request,
    display_name: str = Form(''),
    email: str = Form(''),
    avatar_url: str = Form(''),
    theme: str = Form('dark'),
    preferred_profile: str = Form('basic'),
    default_use_ai: str | None = Form(None),
    user: User | None = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse('/login')

    user.display_name = display_name or user.username
    user.email = email
    user.avatar_url = avatar_url
    user.theme = theme if theme in ['light', 'dark'] else 'dark'
    user.preferred_profile = preferred_profile if preferred_profile in PROFILE_OPTIONS else 'basic'
    user.default_use_ai = bool(default_use_ai)

    db.add(user)
    db.commit()

    return render_template(request, 'profile.html', {
        'error': 'Profile updated successfully',
        'profile_options': PROFILE_OPTIONS,
    }, user=user)


@app.get('/history', response_class=HTMLResponse)
def history_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse('/login')

    scans = db.query(ScanHistory).filter(ScanHistory.user_id == user.id).order_by(ScanHistory.created_at.desc()).all()
    
    scans_with_risk = []
    for scan in scans:
        try:
            result = json.loads(scan.result)
            risk_level = result.get('ai_analysis', {}).get('risk_level', 'unknown')
        except:
            risk_level = 'unknown'
        scan.risk_level = risk_level
        scans_with_risk.append(scan)
    
    return render_template(request, 'history.html', {
        'scans': scans_with_risk,
    }, user=user)


@app.get('/history/{scan_id}', response_class=HTMLResponse)
def history_detail(request: Request, scan_id: int, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse('/login')

    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id, ScanHistory.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')

    result = json.loads(scan.result)
    return render_template(request, 'history_detail.html', {
        'scan': scan,
        'result': result,
    }, user=user)


@app.get('/about', response_class=HTMLResponse)
def about_page(request: Request, user: User | None = Depends(get_current_user)):
    if not user:
        return RedirectResponse('/login')
    return render_template(request, 'about.html', {}, user=user)


class ScanRequest(BaseModel):
    target: str
    profile: str = 'basic'
    web_scan: bool = True


@app.get('/ping')
def ping():
    return {'ok': True, 'service': 'app'}


@app.post('/api/scan')
def scan_api(request: ScanRequest):
    if not request.target:
        raise HTTPException(status_code=400, detail='target is required')

    nmap_result = run_nmap(request.target, request.profile)
    web_checks = {'performed': False, 'findings': [], 'urls': []}
    owasp_mapping = []
    if request.web_scan:
        web_targets = discover_web_targets(request.target, nmap_result)
        if web_targets:
            web_checks = run_web_checks(web_targets)
            owasp_mapping = build_owasp_mapping(web_checks.get('findings', []))

    scan_report = {
        'target': request.target,
        'network_scan': nmap_result,
        'web_checks': web_checks,
        'owasp_mapping': owasp_mapping,
    }
    ai_analysis = analyze_scan_result(scan_report)

    return {
        'target': request.target,
        'network_scan': nmap_result,
        'web_checks': web_checks,
        'owasp_mapping': owasp_mapping,
        'ai_analysis': ai_analysis,
    }


@app.get('/favicon.ico')
def favicon():
    return Response(status_code=204)



if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port)
