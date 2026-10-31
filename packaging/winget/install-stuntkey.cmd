@echo off
rem Installs stuntkey from PyPI: with pipx when it is there, else pip --user.
where pipx >nul 2>nul
if not errorlevel 1 (
  pipx install stuntkey
  exit /b
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -m pip install --user --upgrade stuntkey
  exit /b
)
echo Install Python 3.10+ from python.org, then run again. 1>&2
exit /b 1
