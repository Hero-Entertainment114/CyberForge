[CmdletBinding()]
param(
    [switch]$BuildImage,
    [string]$Image = 'cyberforge/netlab:1.9.5'
)

$ErrorActionPreference = 'Stop'
$results = [ordered]@{
    checked_at = (Get-Date).ToUniversalTime().ToString('o')
    host = [Environment]::OSVersion.VersionString
    docker_cli = $false
    docker_daemon = $false
    linux_engine = $false
    wsl_status = $null
    image_present = $false
    network_none = $false
    raw_socket = $false
    loopback_packet_seen = $false
    default_route_absent = $false
    sample_mounted = $false
    result = 'not_run'
    notes = @()
}

function Invoke-DockerJson([string[]]$DockerArgs) {
    $output = & docker @DockerArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker $($DockerArgs -join ' ') failed: $output" }
    return ($output | Out-String).Trim()
}

try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker CLI not found. Install/start Docker Desktop, then reopen PowerShell.'
    }
    $results.docker_cli = $true
    $versionText = Invoke-DockerJson -DockerArgs @('version', '--format', '{{json .}}')
    $versionObject = $versionText | ConvertFrom-Json
    $infoText = Invoke-DockerJson -DockerArgs @('info', '--format', '{{json .}}')
    $infoObject = $infoText | ConvertFrom-Json
    $results.docker_daemon = $true
    $results.linux_engine = ([string]$infoObject.OSType -eq 'linux')
    if (-not $results.linux_engine) { throw 'Docker daemon is reachable, but the active engine is not Linux containers.' }

    if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
        $wslVersion = (& wsl.exe --version 2>&1 | Out-String).Trim()
        $wslStatus = (& wsl.exe --status 2>&1 | Out-String).Trim()
        $wslList = (& wsl.exe -l -v 2>&1 | Out-String).Trim()
        $results.wsl_status = @{ version = $wslVersion; status = $wslStatus; distributions = $wslList }
    } else {
        $results.notes += 'wsl.exe unavailable; Docker may be using the Hyper-V backend.'
    }

    if ($BuildImage) {
        & docker build --pull -t $Image -f 'sandbox/netlab/Dockerfile' 'sandbox/netlab'
        if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed.' }
    }
    & docker image inspect $Image *> $null
    if ($LASTEXITCODE -ne 0) { throw "Image $Image is not present. Run again with -BuildImage while connected to download its base image." }
    $results.image_present = $true

    # This probe runs only a built-in Python capability check. It does not mount a sample
    # or host directory, does not use --network host, and has no route other than loopback.
    $probe = @'
import json, socket
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind(("lo", 0))
raw.settimeout(1.5)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(b"cyberforge-loopback-probe", ("127.0.0.1", 45454))
frame, _ = raw.recvfrom(65535)
routes = []
with open("/proc/net/route", "r", encoding="ascii") as f:
    next(f, None)
    for line in f:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "00000000":
            routes.append(parts[0])
print(json.dumps({"raw_socket": True, "loopback_packet_seen": len(frame) > 0,
                  "packet_bytes": len(frame), "default_routes": routes,
                  "default_route_absent": len(routes) == 0}))
raw.close(); udp.close()
'@
    $dockerArgs = @(
        'run', '--rm', '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'NET_RAW',
        '--security-opt', 'no-new-privileges', '--read-only', '--pids-limit', '16',
        '--memory', '96m', '--cpus', '0.5', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=4m',
        '--entrypoint', 'python3', $Image, '-c', $probe
    )
    $probeOutput = & docker @dockerArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Container capability probe failed: $probeOutput" }
    $probeText = ($probeOutput | Out-String).Trim()
    $probeJsonLine = ($probeText -split "`r?`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
    if (-not $probeJsonLine) { throw "Probe did not return JSON: $probeText" }
    $probeResult = $probeJsonLine | ConvertFrom-Json
    $results.network_none = $true
    $results.raw_socket = [bool]$probeResult.raw_socket
    $results.loopback_packet_seen = [bool]$probeResult.loopback_packet_seen
    $results.default_route_absent = [bool]$probeResult.default_route_absent
    if (-not ($results.raw_socket -and $results.loopback_packet_seen -and $results.default_route_absent)) {
        throw 'The container started, but one or more loopback/raw-socket/no-default-route checks failed.'
    }
    $results.sample_mounted = $false
    $results.result = 'passed'
    $results.notes += 'This verifies Docker Linux container mode, NET_RAW on lo, one observed loopback packet, and no default route in a --network none container.'
    $results.notes += 'It does not certify container escape resistance, Windows host NIC visibility, or malware behavior.'
} catch {
    $results.result = 'failed'
    $results.notes += $_.Exception.Message
} finally {
    $results | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 'docker-windows-acceptance.json'
    Get-Content 'docker-windows-acceptance.json'
}

if ($results.result -ne 'passed') { exit 1 }
exit 0
