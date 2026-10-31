@echo off
rem stuntkey launcher: runs stuntkey.pyz (next to this file) with Python 3.10+.
setlocal
where py >nul 2>nul && goto py
where python >nul 2>nul && goto python
echo Install Python 3.10+ from python.org, then run again. 1>&2
exit /b 1
:py
py -3 "%~dp0stuntkey.pyz" %*
exit /b %ERRORLEVEL%
:python
python "%~dp0stuntkey.pyz" %*
exit /b %ERRORLEVEL%
