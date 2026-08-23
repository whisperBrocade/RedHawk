@echo off
chcp 65001 >nul
title RedHawk 打包
echo ============================================
echo   RedHawk 独立版打包（PyInstaller）
echo ============================================
echo.

REM 进入 src 目录
cd /d "%~dp0"

REM 检查 pyinstaller
python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo [*] 安装 pyinstaller...
    pip install pyinstaller -q
)

REM 清理旧构建
if exist build rmdir /s /q build
if exist dist\RedHawk rmdir /s /q dist\RedHawk

echo [*] 开始打包（约 1-3 分钟）...
python -m PyInstaller redhawk.spec --noconfirm --clean

if exist dist\RedHawk\RedHawk.exe (
    echo.
    echo [OK] 打包成功！
    echo      可执行文件: dist\RedHawk\RedHawk.exe
    echo      双击即可启动独立版 RedHawk（脱离浏览器）
    echo.
    echo [*] 注意：首次使用请将 dist\RedHawk 目录加入杀软信任区
) else (
    echo.
    echo [X] 打包失败，请查看上方错误信息
)
pause
