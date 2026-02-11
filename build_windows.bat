@echo off
echo Building ApkDetecter for Windows...
pip install -r requirements.txt
pip install pyinstaller Pillow

echo Cleaning up previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo Running PyInstaller...
pyinstaller --noconsole --onefile --clean --name "ApkDetecter" --icon "Resources/logo.png" --add-data "Resources;Resources" --add-data "libs/androguard/core/resources/public.xml;androguard/core/resources" --add-data "libs/androguard/core/api_specific_resources;androguard/core/api_specific_resources" --paths "." --paths "libs" --hidden-import GUI --hidden-import GUI.MainForm --hidden-import GUI.AppInfoWidget --hidden-import Core --hidden-import Core.ApkAnalyzer --hidden-import Core.DeepScanner --hidden-import Core.IpaAnalyzer ApkDetecter.py

echo Build complete!
echo The executable is located in dist\ApkDetecter.exe
pause
