@REM set powershell exec policy
powershell -Command "Start-Process powershell -Verb runAs -ArgumentList ""-Command Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"""
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
