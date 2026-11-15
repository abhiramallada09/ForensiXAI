@echo off
title ForensiX AI - Backend Server
echo ========================================================
echo   Starting ForensiX AI Backend Server (FastAPI)
echo   Academic Project Title:
echo   Memory Forensics for Volatile Data Analysis via
echo   Deep Learning-based Deleted File & Timestamp Reconstruction
echo ========================================================
echo.
cd /d "%~dp0"

REM Check if py launcher is available and has required packages
py -c "import fastapi, torch, joblib" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Using Python Launcher (py)...
    py -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
    goto end
)

REM Fallback to .venv python
if exist ".\.venv\Scripts\python.exe" (
    echo Using Virtual Environment Python (.venv)...
    ".\.venv\Scripts\python.exe" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
    goto end
)

REM Fallback to system python
echo Using System Python...
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

:end
pause

