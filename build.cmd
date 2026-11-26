@echo off
rem Builds the portable single-file NetWarden.exe into .\dist
rem Requirements: Windows 10/11 x64 and the free .NET 8 SDK (winget install Microsoft.DotNet.SDK.8)
rem Usage: build.cmd            (run tests, then build)
rem        build.cmd notest     (skip tests)
rem Everything is also written to build.log next to this file.
setlocal
cd /d "%~dp0"

if not defined NW_BUILD_LOGGING (
  set NW_BUILD_LOGGING=1
  echo Building NetWarden... this takes a few minutes the first time. Output: build.log
  call "%~f0" %* > "%~dp0build.log" 2>&1
  type "%~dp0build.log" | more +0 > nul
  findstr /c:"BUILD SUCCEEDED" "%~dp0build.log" > nul && (echo. & echo BUILD SUCCEEDED: %~dp0dist\NetWarden.exe) || (echo. & echo BUILD FAILED - see build.log)
  pause
  exit /b
)

where dotnet >nul 2>nul
if errorlevel 1 (
  echo The .NET 8 SDK was not found.
  echo Install it with:  winget install Microsoft.DotNet.SDK.8
  exit /b 1
)
dotnet --list-sdks

if /i not "%~1"=="notest" (
  echo === Running tests ===
  dotnet test tests\NetWarden.Tests\NetWarden.Tests.csproj -c Release
  if errorlevel 1 (echo TESTS FAILED & exit /b 1)
)

echo === Building portable NetWarden.exe ===
dotnet publish src\NetWarden.App\NetWarden.App.csproj -c Release -o dist
if errorlevel 1 (echo PUBLISH FAILED & exit /b 1)

echo BUILD SUCCEEDED
endlocal
