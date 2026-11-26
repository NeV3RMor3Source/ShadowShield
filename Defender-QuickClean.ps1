#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Быстрая проверка и очистка ПК средствами Microsoft Defender.

.DESCRIPTION
    Скрипт управляет встроенным Microsoft Defender через официальный модуль Defender:
      1. Проверяет состояние Defender, показывает исключения и разрешённые вами угрозы.
      2. Обновляет сигнатуры.
      3. Запускает проверку (быструю, полную, одну папку или офлайн).
      4. Перед удалением показывает список найденного и требует явного подтверждения.
      5. Удаляет угрозы, не трогая то, что вы разрешили вручную.

    Исключения (папки, файлы, расширения, процессы) Defender пропускает сам.
    Разрешённые вами угрозы («Allowed» в журнале защиты) скрипт не удаляет: если
    среди активных угроз есть разрешённая, автоматическое удаление отменяется.

.PARAMETER ScanType
    Quick (по умолчанию, самая быстрая), Full (полная, долгая) или Offline
    (перезагрузка и проверка до загрузки Windows — см. раздел "Офлайн-проверка").

.PARAMETER Path
    Проверить только указанную папку или файл (быстрее всего для точечной проверки).

.PARAMETER ReportOnly
    Только найти и показать угрозы, ничего не удалять.

.PARAMETER Force
    Не спрашивать подтверждение перед удалением угроз (для автоматизации/задач по расписанию).

.PARAMETER EnableProtection
    Включить защиту в реальном времени, блокировку потенциально нежелательных
    приложений (PUA) и облачную защиту.

.PARAMETER SkipUpdate
    Не обновлять сигнатуры перед проверкой.

.NOTES
    Сделать так, чтобы уже работающий вирус не мог "увидеть" или остановить проверку,
    штатными средствами PowerShell нельзя: любой приём для этого (скрытие процесса,
    маскировка скрипта и т.п.) — это те же методы, которыми вирусы прячутся сами, и
    такой код этот скрипт сознательно не включает. Вместо этого используйте два
    официальных механизма Defender, которые дают такую защиту по-настоящему:
      - Защита от несанкционированного доступа (Tamper Protection) — не даёт
        вредоносным программам и даже администратору через обычные команды
        отключить Defender или изменить его настройки. Включается только вручную:
        Безопасность Windows -> Защита от вирусов и угроз -> Параметры защиты от
        вирусов и угроз -> Управление настройками -> Защита от несанкционированного
        доступа.
      - Автономная проверка Defender (-ScanType Offline) — компьютер перезагружается
        в отдельную среду до загрузки Windows, поэтому ни один вирус из основной
        системы физически не запущен и не может ни увидеть проверку, ни помешать ей.

.EXAMPLE
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Defender-QuickClean.ps1

.EXAMPLE
    .\Defender-QuickClean.ps1 -Path "$env:USERPROFILE\Downloads" -ReportOnly

.EXAMPLE
    .\Defender-QuickClean.ps1 -ScanType Offline
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Full', 'Offline')]
    [string]$ScanType = 'Quick',
    [string]$Path,
    [switch]$ReportOnly,
    [switch]$Force,
    [switch]$EnableProtection,
    [switch]$SkipUpdate
)

$ErrorActionPreference = 'Stop'

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[x] $m" -ForegroundColor Red }

$sw = [System.Diagnostics.Stopwatch]::StartNew()

try {
    Write-Host "`n=== Defender Quick Clean ===`n" -ForegroundColor Magenta

    # ---------- 1. Доступность Defender ----------
    if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
        Fail "Команды Microsoft Defender недоступны на этом компьютере."
        return
    }

    try   { $st = Get-MpComputerStatus }
    catch {
        Fail "Служба Defender недоступна. Возможно, установлен сторонний антивирус или Defender отключён политикой."
        return
    }

    if (-not $st.AntivirusEnabled) {
        Warn "Антивирус Defender выключен. Проверка может не сработать."
    }
    if ($st.AMRunningMode -and $st.AMRunningMode -ne 'Normal') {
        Warn "Defender работает в режиме '$($st.AMRunningMode)' (обычно это значит, что основной антивирус - сторонний). Удаление угроз может быть недоступно."
    }
    if ($st.IsTamperProtected) {
        Info "Защита от несанкционированного доступа (Tamper Protection) включена - это хорошо, вирус не сможет тайно отключить Defender."
    } else {
        Warn "Защита от несанкционированного доступа выключена. Рекомендуется включить её вручную в Безопасности Windows (см. блок NOTES в справке скрипта: Get-Help .\Defender-QuickClean.ps1 -Full)."
    }

    # ---------- 2. Защита в реальном времени ----------
    if ($EnableProtection) {
        Info "Включаю защиту в реальном времени, блокировку PUA и облачную защиту..."
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Set-MpPreference -PUAProtection Enabled
            Set-MpPreference -MAPSReporting Advanced
            Ok "Защита включена."
        } catch {
            Warn "Не удалось изменить настройки (возможно, включена защита от подделки): $($_.Exception.Message)"
        }
    }
    elseif (-not $st.RealTimeProtectionEnabled) {
        Warn "Защита в реальном времени выключена, новые файлы не блокируются автоматически. Запустите скрипт с -EnableProtection."
    }

    # ---------- 3. Ваши исключения ----------
    $pref    = Get-MpPreference
    $exPaths = @($pref.ExclusionPath)      | Where-Object { $_ }
    $exExt   = @($pref.ExclusionExtension) | Where-Object { $_ }
    $exProc  = @($pref.ExclusionProcess)   | Where-Object { $_ }
    Info ("Исключения Defender: папки/файлы - {0}, расширения - {1}, процессы - {2}. Они будут пропущены при проверке." -f `
        $exPaths.Count, $exExt.Count, $exProc.Count)

    # ---------- 4. Разрешённые вами угрозы ----------
    # ThreatStatusID = 5 означает «Allowed» (разрешено пользователем)
    $allowedIds = @()
    try {
        $allowedIds = @(Get-MpThreatDetection |
            Where-Object { $_.ThreatStatusID -eq 5 } |
            Select-Object -ExpandProperty ThreatID -Unique)
    } catch { }
    Info "Разрешённых вами угроз в журнале: $($allowedIds.Count). Скрипт их не удаляет."

    # ---------- 5. Офлайн-проверка (отдельная ветка: перезагрузка) ----------
    if ($ScanType -eq 'Offline') {
        Warn "Будет запущена автономная проверка Defender: компьютер сейчас перезагрузится"
        Warn "и проверит систему ДО загрузки Windows (это может занять 15-30+ минут)."
        Warn "Сохраните все открытые документы."
        if (-not $Force) {
            $answer = Read-Host "Введите 'да' для перезагрузки и запуска офлайн-проверки"
            if ($answer -ne 'да') { Info "Отменено пользователем."; return }
        }
        Start-MpWDOScan
        Ok "Автономная проверка запущена, компьютер перезагружается."
        return
    }

    # ---------- 6. Обновление сигнатур ----------
    if (-not $SkipUpdate) {
        Info "Обновляю сигнатуры Defender..."
        try   { Update-MpSignature; Ok "Сигнатуры обновлены." }
        catch { Warn "Не удалось обновить сигнатуры (нет интернета?): $($_.Exception.Message)" }
    }

    # ---------- 7. Проверка ----------
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { Fail "Путь не найден: $Path"; return }
        Info "Проверяю: $Path"
        Start-MpScan -ScanType CustomScan -ScanPath $Path
    }
    elseif ($ScanType -eq 'Full') {
        Info "Запускаю полную проверку (может занять много времени)..."
        Start-MpScan -ScanType FullScan
    }
    else {
        Info "Запускаю быструю проверку..."
        Start-MpScan -ScanType QuickScan
    }
    Ok "Проверка завершена."

    # ---------- 8. Результаты ----------
    $active = @(Get-MpThreat | Where-Object { $_.IsActive })
    if ($active.Count -eq 0) {
        Ok "Активных угроз не найдено."
        return
    }

    $skipped  = @($active | Where-Object { $allowedIds -contains $_.ThreatID })
    $toRemove = @($active | Where-Object { $allowedIds -notcontains $_.ThreatID })

    Warn "Найдено активных угроз: $($active.Count)"
    foreach ($t in $active) {
        $mark = if ($allowedIds -contains $t.ThreatID) { ' [РАЗРЕШЕНА ВАМИ - не будет тронута]' } else { '' }
        Write-Host ("    - {0} (ID {1}){2}" -f $t.ThreatName, $t.ThreatID, $mark) -ForegroundColor Yellow
        foreach ($r in @($t.Resources)) { Write-Host "        $r" }
    }

    if ($ReportOnly) {
        Info "Режим -ReportOnly: ничего не удаляю."
        return
    }

    # ---------- 9. Разрешённые угрозы среди найденного -> удаление отменяется ----------
    if ($skipped.Count -gt 0) {
        Warn "Среди активных угроз есть разрешённые вами ($($skipped.Count) шт.). Автоудаление отменено, чтобы их не затронуть."
        Warn "Удалите нужные угрозы вручную: Безопасность Windows -> Защита от вирусов и угроз -> Журнал защиты."
        return
    }

    # ---------- 10. Явное подтверждение перед удалением ----------
    if (-not $Force) {
        Write-Host ""
        Warn "Будут удалены ВСЕ угрозы из списка выше (их $($toRemove.Count)), ничего из разрешённого вами не затронется."
        $answer = Read-Host "Введите 'да' для удаления, любой другой ввод отменяет действие"
        if ($answer -ne 'да') {
            Info "Удаление отменено пользователем."
            return
        }
    }

    # ---------- 11. Удаление ----------
    Info "Удаляю найденные угрозы..."
    Remove-MpThreat
    Start-Sleep -Seconds 2

    $left = @(Get-MpThreat | Where-Object { $_.IsActive })
    if ($left.Count -eq 0) {
        Ok "Все активные угрозы удалены."
    } else {
        Warn "Осталось угроз: $($left.Count). Перезагрузите ПК и повторите проверку, либо запустите: .\Defender-QuickClean.ps1 -ScanType Offline"
    }
}
catch {
    Fail "Ошибка: $($_.Exception.Message)"
}
finally {
    $sw.Stop()
    Info ("Затрачено времени: {0:mm\:ss}" -f $sw.Elapsed)
}
