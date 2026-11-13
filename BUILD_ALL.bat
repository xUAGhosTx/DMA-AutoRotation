@echo off
title PORTOLAN DMA BUILD PIPELINE
cd /d "%~dp0wow_dma_app"
echo [*] Compiling release binaries (dma_daemon, dma_gui, dma_xref_gui, dma_inspector)...
cargo build --release --bin dma_daemon --bin dma_gui --bin dma_xref_gui --bin dma_inspector

if %errorlevel% neq 0 (
    echo.
    echo [-] Ошибка компиляции Cargo. Проверьте вывод выше.
    pause
    exit /b %errorlevel%
)

echo.
echo [*] Синхронизация бинарников в E:\WoW DMA\DEV\BIN...
copy /y target\release\dma_daemon.exe ..\BIN\dma_daemon.exe >nul
copy /y target\release\dma_gui.exe ..\BIN\dma_gui.exe >nul
copy /y target\release\dma_xref_gui.exe ..\BIN\dma_xref_gui.exe >nul
copy /y target\release\dma_inspector.exe ..\BIN\dma_inspector.exe >nul

echo [✓] Все бинарники успешно обновлены в E:\WoW DMA\DEV\BIN!
echo.
timeout /t 3

