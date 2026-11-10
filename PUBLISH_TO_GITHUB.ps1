param([Parameter(Mandatory=$true)][string]$RepositoryUrl)
$ErrorActionPreference = 'Stop'
git init -b main
git add .
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) { throw 'Nothing to commit.' }
git commit -m 'Publish CyberForge AIO v1.9.9.1'
git remote add origin $RepositoryUrl
git push -u origin main
if ($LASTEXITCODE -ne 0) { throw 'Git push failed. Check GitHub authentication and repository permissions.' }
