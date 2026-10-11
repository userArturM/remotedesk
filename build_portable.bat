@echo off
chcp 65001 >nul
title Сборка remote-Art (портативная версия)

where python >nul 2>nul
if errorlevel 1 (
    echo Python не найден. Установите его с https://www.python.org/downloads/
    echo При установке отметьте "Add python.exe to PATH".
    pause
    exit /b 1
)

echo [1/3] Установка библиотек...
python -m pip install --upgrade pip
python -m pip install customtkinter mss pillow pynput cryptography pyinstaller
if errorlevel 1 ( echo Не удалось установить библиотеки. & pause & exit /b 1 )

echo [2/3] Создание иконки...
python "%~dp0remote_art.py" --make-icon "%~dp0icon.ico"

echo [3/3] Сборка remote-Art.exe...
python -m PyInstaller --onefile --noconsole --name remote-Art --icon "%~dp0icon.ico" --collect-all customtkinter --hidden-import pynput.keyboard._win32 --hidden-import pynput.mouse._win32 "%~dp0remote_art.py"
if errorlevel 1 ( echo Сборка не удалась. & pause & exit /b 1 )

echo.
echo Готово! Файл: %~dp0dist\remote-Art.exe
explorer "%~dp0dist"
pause
