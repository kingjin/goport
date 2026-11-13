@echo off
rem Build goport.exe (pure Go, no cgo, no C compiler required).
setlocal
set "ROOT=%~dp0"
set "CGO_ENABLED=0"
set "GOFLAGS="

where go >nul 2>nul
if errorlevel 1 goto nogo

if not exist "%ROOT%bin" mkdir "%ROOT%bin"
echo [*] building bin\goport.exe ...
go build -trimpath -ldflags "-s -w" -o "%ROOT%bin\goport.exe" "%ROOT%cmd\goport"
if errorlevel 1 goto fail
echo [ok] %ROOT%bin\goport.exe
echo.
echo SYN mode needs Administrator rights. Run this in an elevated terminal:
echo    bin\goport.exe -doctor
goto end

:nogo
echo [x] go not found. Install Go 1.21+ or add go.exe to PATH.
exit /b 1

:fail
echo [x] build failed
exit /b 1

:end
endlocal
