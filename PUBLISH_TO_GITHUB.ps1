param([Parameter(Mandatory=$true)][string]$RepositoryUrl)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path LICENSE)) { throw 'Add the project LICENSE before publishing this repository as open source.' }
git init -b main
git add .
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) { throw 'Nothing to commit.' }
git commit -m 'Publish CyberForge Server Edition v2.1.0 Official Stable'
git remote add origin $RepositoryUrl
git push -u origin main
if ($LASTEXITCODE -ne 0) { throw 'Git push failed. Check GitHub authentication and repository permissions.' }
