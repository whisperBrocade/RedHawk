# RedHawk - 一键修复 HTTPS 证书信任（免管理员）
# 用法：右键 -> 使用 PowerShell 运行；或在 PowerShell 中执行 .\fix_ca.ps1
# 说明：只操作 Subject 含 RedHawk 的证书；安装到 CurrentUser\Root（无需管理员）。
# 执行后请彻底重启浏览器（关掉所有窗口再开）。

$ErrorActionPreference = 'Stop'

# 1) 确保 CA 已生成（未生成则由固定 certgen 生成到 %LOCALAPPDATA%\RedHawk\certs）
$py = (Get-Command python -ErrorAction SilentlyContinue | Select-Object -Expand Source)
if (-not $py) { $py = 'python' }
$projSrc = Join-Path $PSScriptRoot 'src'
if (Test-Path $projSrc) {
    $env:PYTHONPATH = $projSrc
    pushd $projSrc
    & $py -c "from redhawk.certgen import get_ca_pem; get_ca_pem(); print('CA ready')"
    popd
}
$crt = Join-Path $env:LOCALAPPDATA 'RedHawk\certs\redhawk-ca.crt'
if (-not (Test-Path $crt)) { Write-Host "[X] 未找到 CA 文件: $crt" -ForegroundColor Red; exit 1 }
Write-Host "[*] 新 CA 文件: $crt"

# 2) 移除旧同名 CA（CurrentUser + LocalMachine）
$old = @(Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match 'RedHawk' }) +
       @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match 'RedHawk' })
if ($old.Count -eq 0) {
    Write-Host "[*] 未发现旧 CA，无需清理"
} else {
    foreach ($c in ($old | Sort-Object Thumbprint -Unique)) {
        try { Remove-Item $c.PSPath -Force -ErrorAction Stop
              Write-Host "[*] 已移除旧 CA: $($c.Subject)  $($c.Thumbprint)" -ForegroundColor Yellow }
        catch { Write-Host "[ ] 移除失败（可能需管理员）: $($c.Thumbprint)  $($_.Exception.Message)" -ForegroundColor Gray }
    }
}

# 3) 安装新 CA 到当前用户信任根（免提权）
certutil -user -addstore Root $crt
if ($LASTEXITCODE -ne 0) { Write-Host "[X] certutil 安装失败（exit $LASTEXITCODE）" -ForegroundColor Red; exit 1 }

# 4) 显示安装后的指纹，便于核对
Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'RedHawk' } |
    Select-Object Subject, Thumbprint, NotAfter | Format-List

Write-Host ""
Write-Host "[OK] 完成。请彻底重启浏览器后重试 https://www.bing.com" -ForegroundColor Green