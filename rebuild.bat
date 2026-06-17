@echo off
cd /d C:\ocii-iris
echo === Rebuild OCII-IRIS (app + nginx) ===
docker-compose up -d --build ocii-iris nginx
echo.
echo Rebuild termine. Attente 8s pour demarrage...
timeout /t 8 /nobreak >nul
echo === Test HTTPS ===
curl -sk https://localhost/ >nul 2>&1
if %errorlevel%==0 (
    echo [OK] HTTPS fonctionne
) else (
    echo [WARN] HTTPS non accessible — test HTTP fallback...
    curl -s http://localhost:5000/ >nul 2>&1
)
echo.
echo === DONE ===
echo Acces : https://localhost (ou https://VOTRE_IP_LAN)
pause
