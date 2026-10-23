@echo off
chcp 65001 >nul
cd /d "%~dp0"
title رفع تطبيق الفورمة الأصلي
echo ===============================================
echo    رفع تطبيق الفورمة الأصلي على GitHub
echo ===============================================
set "GIT="
where git >nul 2>nul && set "GIT=git"
if not defined GIT if exist "C:\Program Files\Git\cmd\git.exe" set "GIT=C:\Program Files\Git\cmd\git.exe"
if not defined GIT if exist "%LocalAppData%\Programs\Git\cmd\git.exe" set "GIT=%LocalAppData%\Programs\Git\cmd\git.exe"
if not defined GIT (
 echo [خطأ] ثبّت Git من https://git-scm.com/download/win
 pause
 exit /b 1
)
echo.
echo الصق رابط مستودع GitHub HTTPS ثم اضغط Enter
set /p REPO="رابط المستودع: "
if "%REPO%"=="" ( echo [خطأ] لم تدخل رابطًا & pause & exit /b 1 )
echo.
echo رفع نسخة نظيفة للتطبيق الأصلي...
if exist ".git" rmdir /s /q ".git"
if exist "node_modules" rmdir /s /q "node_modules"
"%GIT%" init
"%GIT%" add -A
"%GIT%" -c user.email=elforma@example.com -c user.name="ElForma" commit -m "Native Flutter app"
"%GIT%" branch -M main
"%GIT%" remote add origin "%REPO%"
"%GIT%" push -f origin main
if errorlevel 1 (
 echo [خطأ] الرفع فشل. صوّر الشاشة وابعتها.
) else (
 echo.
 echo تم الرفع. افتح Actions على GitHub.
 echo نزّل artifact: elforma-native-android-apk بعد نجاح البناء.
)
pause
