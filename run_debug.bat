@echo off
cd /d C:\ocii-iris
echo === Rebuilding Flask container (final) ===
docker-compose up -d --build ocii-iris
echo === DONE ===
timeout /t 3 /nobreak >nul
