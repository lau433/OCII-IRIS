@echo off
echo === Ouverture ports firewall Windows pour OCII-IRIS ===
echo.
echo Ajout regle HTTPS (443)...
netsh advfirewall firewall add rule name="OCII-IRIS HTTPS" dir=in action=allow protocol=tcp localport=443
echo.
echo Ajout regle HTTP redirect (80)...
netsh advfirewall firewall add rule name="OCII-IRIS HTTP" dir=in action=allow protocol=tcp localport=80
echo.
echo === Ports 80 et 443 ouverts ===
echo.
echo Pour trouver ton IP LAN :
ipconfig | findstr /C:"IPv4"
echo.
echo Tes superieurs peuvent acceder a : https://TON_IP_CI_DESSUS
pause
