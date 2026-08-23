$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$srcUi = Join-Path $repo 'src\ui'
$runtime = Join-Path $repo 'runtime'
$distRoot = Join-Path $repo 'dist'
$dist = Join-Path $distRoot 'SecretoBoot_V9'

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

$cscCandidates = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$csc = $cscCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $csc) { throw 'Microsoft .NET Framework C# compiler was not found.' }

if (Test-Path -LiteralPath $dist) { Remove-Item -LiteralPath $dist -Recurse -Force }
New-Item -ItemType Directory -Path $dist -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $runtime '*') -Destination $dist -Recurse -Force

$programTemplate = Get-Content -LiteralPath (Join-Path $srcUi 'Program.cs') -Raw
$program = $programTemplate.Replace('__BRIDGE_SHA256__', (Get-Sha256 (Join-Path $dist 'UiDiscoveryBridge.ps1')))
$program = $program.Replace('__DEPLOYMENT_SHA256__', (Get-Sha256 (Join-Path $dist 'Invoke-SecretoBootDeployment.ps1')))
$program = $program.Replace('__MANUAL_CONFIRMATION_SHA256__', (Get-Sha256 (Join-Path $dist 'Confirm-SecretoBootManualTarget.ps1')))
$generated = Join-Path $srcUi 'Program.generated.cs'
[IO.File]::WriteAllText($generated, $program, [Text.UTF8Encoding]::new($false))

$outExe = Join-Path $dist 'SecretoBoot.exe'
$args = @(
    '/nologo', '/target:winexe', '/optimize+', '/debug-',
    ('/out:' + $outExe),
    ('/win32manifest:' + (Join-Path $srcUi 'app.manifest')),
    '/reference:System.dll', '/reference:System.Core.dll', '/reference:System.Drawing.dll', '/reference:System.Windows.Forms.dll',
    $generated,
    (Join-Path $srcUi 'SecretoBoot.FriendlyNamePolicy.cs'),
    (Join-Path $srcUi 'SecretoBoot.UpgradeActionPolicy.cs')
)

Write-Host 'Building SecretoBoot V9...' -ForegroundColor Cyan
& $csc @args
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outExe)) {
    throw "C# build failed with exit code $LASTEXITCODE"
}

$integrityPath = Join-Path $dist 'package-integrity.json'
$integrity = Get-Content -LiteralPath $integrityPath -Raw | ConvertFrom-Json
$integrity.Files.'SecretoBoot.exe' = Get-Sha256 $outExe
[IO.File]::WriteAllText($integrityPath, (($integrity | ConvertTo-Json -Depth 10) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

# End-user docs and recovery tool
Copy-Item -LiteralPath (Join-Path $repo 'docs\README_EN.md') -Destination (Join-Path $dist 'README_EN.md') -Force
Copy-Item -LiteralPath (Join-Path $repo 'docs\README_FR.md') -Destination (Join-Path $dist 'README_FR.md') -Force
Copy-Item -LiteralPath (Join-Path $repo 'docs\README_AR.md') -Destination (Join-Path $dist 'README_AR.md') -Force
Copy-Item -LiteralPath (Join-Path $repo 'NOTICE.md') -Destination (Join-Path $dist 'NOTICE.md') -Force
Copy-Item -LiteralPath (Join-Path $repo 'DISCLAIMER.md') -Destination (Join-Path $dist 'DISCLAIMER.md') -Force
Copy-Item -LiteralPath (Join-Path $repo 'THIRD_PARTY_LICENSES.md') -Destination (Join-Path $dist 'THIRD_PARTY_LICENSES.md') -Force
Copy-Item -LiteralPath (Join-Path $repo 'tools\EMERGENCY_RESTORE_NATIVE_WINDOWS.cmd') -Destination (Join-Path $dist 'EMERGENCY_RESTORE_NATIVE_WINDOWS.cmd') -Force

$zip = Join-Path $distRoot 'SecretoBoot_V9_Windows_x64.zip'
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip -CompressionLevel Optimal

$sha = Get-Sha256 $zip
[IO.File]::WriteAllText((Join-Path $distRoot 'SecretoBoot_V9_Windows_x64.sha256'), ($sha + '  SecretoBoot_V9_Windows_x64.zip' + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host 'Build completed.' -ForegroundColor Green
Write-Host ('Release ZIP: ' + $zip)
Write-Host ('SHA-256: ' + $sha)
Write-Host 'No EFI/BCD/NVRAM/BootOrder settings were changed by this build.' -ForegroundColor Green
