@echo off
rem Builds the portable single-file NetWarden.exe into .\dist
rem Requirements: Windows 10/11 x64 and the free .NET 8 SDK (winget install Microsoft.DotNet.SDK.8)
rem Usage: build.cmd            (run tests, then build)
rem        build.cmd notest     (skip tests)
setlocal
cd /d "%~dp0"

where dotnet >nul 2>nul
if errorlevel 1 (
  echo The .NET 8 SDK was not found.
  echo Install it with:  winget install Microsoft.DotNet.SDK.8
  echo or download it from https://dotnet.microsoft.com/download/dotnet/8.0
  exit /b 1
)

if /i not "%~1"=="notest" (
  echo === Running tests ===
  dotnet test tests\NetWarden.Tests\NetWarden.Tests.csproj -c Release
  if errorlevel 1 exit /b 1
)

echo === Building portable NetWarden.exe ===
dotnet publish src\NetWarden.App\NetWarden.App.csproj -c Release -o dist
if errorlevel 1 exit /b 1

echo.
echo Done: %cd%\dist\NetWarden.exe
echo Copy NetWarden.exe anywhere (USB stick, tools share) and run it. Data is kept in a NetWarden-data folder next to it.
endlocal
