#!powershell

# Copyright: (c) 2026, securitygoblin
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        path = @{
            type     = "path"
            required = $true
        }
        job_name = @{
            type     = "str"
            required = $true
        }
        state = @{
            type     = "str"
            required = $true
            choices  = @("started", "completed")
        }
        status = @{
            type    = "str"
            default = "ok"
            choices = @("ok", "failed", "unreachable")
        }
        health = @{
            type    = "str"
            default = "healthy"
            choices = @("healthy", "degraded", "unhealthy")
        }
        source = @{
            type    = "dict"
            default = @{}
            options = @{
                ansible_controller = @{ type = "str"; default = "unknown" }
                playbook           = @{ type = "str"; default = "unknown" }
                run_id             = @{ type = "str"; default = "" }
                environment        = @{ type = "str"; default = "unknown" }
                ansible_version    = @{ type = "str"; default = "unknown" }
            }
        }
        summary = @{
            type    = "dict"
            default = @{}
            options = @{
                ok          = @{ type = "int"; default = 0 }
                changed     = @{ type = "int"; default = 0 }
                failed      = @{ type = "int"; default = 0 }
                unreachable = @{ type = "int"; default = 0 }
            }
        }
        host_info = @{
            type    = "dict"
            default = @{}
            options = @{
                software_installed = @{ type = "list"; elements = "str"; default = @() }
                config_applied     = @{ type = "list"; elements = "str"; default = @() }
                siem = @{
                    type    = "dict"
                    default = @{}
                    options = @{
                        onboarded      = @{ type = "bool"; default = $false }
                        collector      = @{ type = "str"; default = "" }
                        syslog_running = @{ type = "bool"; default = $false }
                        forwarding_ok  = @{ type = "bool"; default = $false }
                        last_seen      = @{ type = "str"; default = "" }
                    }
                }
            }
        }
        job_id = @{
            type    = "str"
            default = ""
        }
        create_directory = @{
            type    = "bool"
            default = $true
        }
        mutex_timeout_ms = @{
            type    = "int"
            default = 30000
        }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

# ── Helper: Get current UTC timestamp in ISO 8601 ──────────────────────────
function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

# ── Helper: Generate a job ID like host-HOSTNAME-12345 ─────────────────────
function New-JobId {
    $hostname = $env:COMPUTERNAME.ToLower()
    $suffix   = Get-Random -Minimum 10000 -Maximum 99999
    return "host-$hostname-$suffix"
}

# ── Helper: Create a blank JSON log structure ──────────────────────────────
function New-JobLogStructure {
    param([hashtable]$Source)

    $src = @{
        ansible_controller = if ($Source.ansible_controller) { $Source.ansible_controller } else { "unknown" }
        playbook           = if ($Source.playbook)           { $Source.playbook }           else { "unknown" }
        run_id             = if ($Source.run_id)             { $Source.run_id }             else { "" }
        environment        = if ($Source.environment)        { $Source.environment }        else { "unknown" }
        ansible_version    = if ($Source.ansible_version)    { $Source.ansible_version }    else { "unknown" }
    }

    return [ordered]@{
        schema_version = "1.0"
        generated_at   = Get-UtcTimestamp
        source         = [ordered]@{
            ansible_controller = $src.ansible_controller
            playbook           = $src.playbook
            run_id             = $src.run_id
            environment        = $src.environment
            ansible_version    = $src.ansible_version
        }
        jobs = @()
        host = [ordered]@{
            name               = $env:COMPUTERNAME.ToLower()
            status             = "unknown"
            health             = "unknown"
            software_installed = @()
            config_applied     = @()
            siem               = [ordered]@{
                onboarded      = $false
                collector      = ""
                syslog_running = $false
                forwarding_ok  = $false
                last_seen      = ""
            }
        }
    }
}

# ── Helper: Create a blank job entry ───────────────────────────────────────
function New-JobEntry {
    param(
        [string]$JobName,
        [string]$JobId
    )

    return [ordered]@{
        job_name    = $JobName
        job_id      = $JobId
        status      = "running"
        started_at  = ""
        finished_at = ""
        duration_sec = 0
        health      = "healthy"
        summary     = [ordered]@{
            ok          = 0
            changed     = 0
            failed      = 0
            unreachable = 0
        }
        maintenance_window = [ordered]@{
            started_at = ""
            ended_at   = ""
            ended      = $false
        }
    }
}

# ── Helper: Recalculate host-level status and health from all jobs ─────────
function Update-HostAggregate {
    param([hashtable]$JobLog)

    $jobs = $JobLog.jobs

    if ($jobs.Count -eq 0) {
        $JobLog.host.status = "unknown"
        $JobLog.host.health = "unknown"
        return
    }

    # Status: failed > running > ok
    $hasFailed  = $false
    $hasRunning = $false
    foreach ($j in $jobs) {
        if ($j.status -eq "failed" -or $j.status -eq "unreachable") { $hasFailed = $true }
        if ($j.status -eq "running") { $hasRunning = $true }
    }

    if ($hasFailed)       { $JobLog.host.status = "failed" }
    elseif ($hasRunning)  { $JobLog.host.status = "running" }
    else                  { $JobLog.host.status = "ok" }

    # Health: unhealthy > degraded > healthy
    $hasUnhealthy = $false
    $hasDegraded  = $false
    foreach ($j in $jobs) {
        if ($j.health -eq "unhealthy") { $hasUnhealthy = $true }
        if ($j.health -eq "degraded")  { $hasDegraded = $true }
    }

    if ($hasUnhealthy)    { $JobLog.host.health = "unhealthy" }
    elseif ($hasDegraded) { $JobLog.host.health = "degraded" }
    else                  { $JobLog.host.health = "healthy" }
}

# ── Main logic ─────────────────────────────────────────────────────────────

$path             = $module.Params.path
$jobName          = $module.Params.job_name
$state            = $module.Params.state
$mutexTimeoutMs   = $module.Params.mutex_timeout_ms

# Ensure parent directory exists
if ($module.Params.create_directory) {
    $directory = Split-Path -Path $path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        if (-not $module.CheckMode) {
            try {
                New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            catch {
                $module.FailJson("Failed to create directory '$directory': $_", $_)
            }
        }
    }
}

# Create named mutex for thread-safe file access
$safeName  = $path -replace '[\\/:*?"<>|]', '_'
$mutexName = "Global\AnsibleJobLog_$safeName"
$mutex     = $null
$acquired  = $false

try {
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)

    try {
        $acquired = $mutex.WaitOne($mutexTimeoutMs)
    }
    catch [System.Threading.AbandonedMutexException] {
        # Previous holder crashed — we now own the mutex
        $acquired = $true
    }

    if (-not $acquired) {
        $module.FailJson("Failed to acquire file lock for '$path' within ${mutexTimeoutMs}ms. Another process may be holding the lock.")
    }

    # ── Read or initialise the JSON structure ──────────────────────────
    $jobLog = $null
    if (Test-Path -LiteralPath $path) {
        try {
            $raw    = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop

            # Convert PSCustomObject to ordered hashtable for easier manipulation
            $jobLog = [ordered]@{
                schema_version = if ($parsed.schema_version) { $parsed.schema_version } else { "1.0" }
                generated_at   = if ($parsed.generated_at)   { $parsed.generated_at }   else { Get-UtcTimestamp }
                source         = [ordered]@{
                    ansible_controller = if ($parsed.source.ansible_controller) { $parsed.source.ansible_controller } else { "unknown" }
                    playbook           = if ($parsed.source.playbook)           { $parsed.source.playbook }           else { "unknown" }
                    run_id             = if ($parsed.source.run_id)             { $parsed.source.run_id }             else { "" }
                    environment        = if ($parsed.source.environment)        { $parsed.source.environment }        else { "unknown" }
                    ansible_version    = if ($parsed.source.ansible_version)    { $parsed.source.ansible_version }    else { "unknown" }
                }
                jobs = @()
                host = [ordered]@{
                    name               = if ($parsed.host.name)               { $parsed.host.name }               else { $env:COMPUTERNAME.ToLower() }
                    status             = if ($parsed.host.status)             { $parsed.host.status }             else { "unknown" }
                    health             = if ($parsed.host.health)             { $parsed.host.health }             else { "unknown" }
                    software_installed = if ($parsed.host.software_installed) { @($parsed.host.software_installed) } else { @() }
                    config_applied     = if ($parsed.host.config_applied)     { @($parsed.host.config_applied) }     else { @() }
                    siem               = [ordered]@{
                        onboarded      = if ($null -ne $parsed.host.siem.onboarded)      { $parsed.host.siem.onboarded }      else { $false }
                        collector      = if ($parsed.host.siem.collector)                 { $parsed.host.siem.collector }      else { "" }
                        syslog_running = if ($null -ne $parsed.host.siem.syslog_running)  { $parsed.host.siem.syslog_running } else { $false }
                        forwarding_ok  = if ($null -ne $parsed.host.siem.forwarding_ok)   { $parsed.host.siem.forwarding_ok }  else { $false }
                        last_seen      = if ($parsed.host.siem.last_seen)                 { $parsed.host.siem.last_seen }      else { "" }
                    }
                }
            }

            # Convert existing jobs from PSCustomObject to ordered hashtables
            if ($parsed.jobs) {
                foreach ($existingJob in $parsed.jobs) {
                    $j = [ordered]@{
                        job_name     = $existingJob.job_name
                        job_id       = $existingJob.job_id
                        status       = $existingJob.status
                        started_at   = $existingJob.started_at
                        finished_at  = $existingJob.finished_at
                        duration_sec = $existingJob.duration_sec
                        health       = $existingJob.health
                        summary      = [ordered]@{
                            ok          = if ($null -ne $existingJob.summary.ok)          { [int]$existingJob.summary.ok }          else { 0 }
                            changed     = if ($null -ne $existingJob.summary.changed)     { [int]$existingJob.summary.changed }     else { 0 }
                            failed      = if ($null -ne $existingJob.summary.failed)      { [int]$existingJob.summary.failed }      else { 0 }
                            unreachable = if ($null -ne $existingJob.summary.unreachable) { [int]$existingJob.summary.unreachable } else { 0 }
                        }
                        maintenance_window = [ordered]@{
                            started_at = $existingJob.maintenance_window.started_at
                            ended_at   = $existingJob.maintenance_window.ended_at
                            ended      = if ($null -ne $existingJob.maintenance_window.ended) { $existingJob.maintenance_window.ended } else { $false }
                        }
                    }
                    $jobLog.jobs += $j
                }
            }
        }
        catch {
            $module.FailJson("Failed to parse existing JSON file at '$path'. File may be corrupted: $_", $_)
        }
    }
    else {
        $jobLog = New-JobLogStructure -Source $module.Params.source
    }

    # ── Update source metadata (merge user-supplied values) ────────────
    $sourceParam = $module.Params.source
    if ($sourceParam) {
        foreach ($key in @("ansible_controller", "playbook", "environment", "ansible_version")) {
            if ($sourceParam[$key] -and $sourceParam[$key] -ne "unknown") {
                $jobLog.source[$key] = $sourceParam[$key]
            }
        }
        if ($sourceParam["run_id"]) {
            $jobLog.source.run_id = $sourceParam["run_id"]
        }
    }

    # Auto-generate run_id if still empty
    if (-not $jobLog.source.run_id) {
        $ts = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
        $jobLog.source.run_id = "$ts-$jobName"
    }

    # ── Find or create the job entry ───────────────────────────────────
    $jobIndex = -1
    for ($i = 0; $i -lt $jobLog.jobs.Count; $i++) {
        if ($jobLog.jobs[$i].job_name -eq $jobName) {
            $jobIndex = $i
            break
        }
    }

    if ($jobIndex -eq -1) {
        # Determine job_id
        $jid = if ($module.Params.job_id) { $module.Params.job_id } else { New-JobId }
        $newJob = New-JobEntry -JobName $jobName -JobId $jid
        $jobLog.jobs += $newJob
        $jobIndex = $jobLog.jobs.Count - 1
    }

    $job = $jobLog.jobs[$jobIndex]

    # ── Apply state-specific updates ───────────────────────────────────
    $now = Get-UtcTimestamp

    if ($state -eq "started") {
        $job.started_at  = $now
        $job.finished_at = ""
        $job.duration_sec = 0
        $job.status      = "running"
        $job.health      = $module.Params.health
        $job.maintenance_window.started_at = $now
        $job.maintenance_window.ended_at   = ""
        $job.maintenance_window.ended      = $false

        # Reset summary on new run
        $job.summary.ok          = 0
        $job.summary.changed     = 0
        $job.summary.failed      = 0
        $job.summary.unreachable = 0

        # Update job_id if user provided one
        if ($module.Params.job_id) {
            $job.job_id = $module.Params.job_id
        }
    }
    elseif ($state -eq "completed") {
        $job.finished_at = $now
        $job.status      = $module.Params.status
        $job.health      = $module.Params.health
        $job.maintenance_window.ended_at = $now
        $job.maintenance_window.ended    = $true

        # Calculate duration if we have a started_at
        if ($job.started_at) {
            try {
                $startTime = [datetime]::Parse($job.started_at).ToUniversalTime()
                $endTime   = [datetime]::Parse($job.finished_at).ToUniversalTime()
                $job.duration_sec = [int][math]::Floor(($endTime - $startTime).TotalSeconds)
            }
            catch {
                $module.Warn("Could not calculate duration: $_")
                $job.duration_sec = 0
            }
        }
        else {
            $module.Warn("Job '$jobName' has no started_at timestamp. Duration set to 0.")
        }

        # Update summary
        $summaryParam = $module.Params.summary
        if ($summaryParam) {
            $job.summary.ok          = [int]$summaryParam.ok
            $job.summary.changed     = [int]$summaryParam.changed
            $job.summary.failed      = [int]$summaryParam.failed
            $job.summary.unreachable = [int]$summaryParam.unreachable
        }
    }

    # Write back the updated job
    $jobLog.jobs[$jobIndex] = $job

    # ── Merge host_info if provided ────────────────────────────────────
    $hostInfo = $module.Params.host_info
    if ($hostInfo) {
        if ($hostInfo.software_installed -and $hostInfo.software_installed.Count -gt 0) {
            $jobLog.host.software_installed = @($hostInfo.software_installed)
        }
        if ($hostInfo.config_applied -and $hostInfo.config_applied.Count -gt 0) {
            $jobLog.host.config_applied = @($hostInfo.config_applied)
        }
        if ($hostInfo.siem) {
            $s = $hostInfo.siem
            if ($null -ne $s.onboarded)      { $jobLog.host.siem.onboarded      = $s.onboarded }
            if ($s.collector)                 { $jobLog.host.siem.collector      = $s.collector }
            if ($null -ne $s.syslog_running)  { $jobLog.host.siem.syslog_running = $s.syslog_running }
            if ($null -ne $s.forwarding_ok)   { $jobLog.host.siem.forwarding_ok  = $s.forwarding_ok }
            if ($s.last_seen)                 { $jobLog.host.siem.last_seen      = $s.last_seen }
        }
    }

    # ── Recalculate host-level aggregates ──────────────────────────────
    Update-HostAggregate -JobLog $jobLog

    # ── Update generated_at ────────────────────────────────────────────
    $jobLog.generated_at = Get-UtcTimestamp

    # ── Write the file (unless check mode) ─────────────────────────────
    if (-not $module.CheckMode) {
        $tempPath = "$path.tmp-$([guid]::NewGuid())"
        try {
            $json = $jobLog | ConvertTo-Json -Depth 10 -Compress:$false
            [System.IO.File]::WriteAllText($tempPath, $json, [System.Text.Encoding]::UTF8)
            Move-Item -LiteralPath $tempPath -Destination $path -Force -ErrorAction Stop
        }
        catch {
            if (Test-Path -LiteralPath $tempPath) {
                Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
            }
            $module.FailJson("Failed to write JSON log file: $_", $_)
        }
    }

    $module.Result.changed  = $true
    $module.Result.path     = $path
    $module.Result.job_name = $jobName
    $module.Result.state    = $state
    $module.Result.job_id   = $jobLog.jobs[$jobIndex].job_id
}
catch {
    $module.FailJson("Error updating job log: $_", $_)
}
finally {
    if ($mutex) {
        if ($acquired) {
            try { $mutex.ReleaseMutex() } catch {}
        }
        $mutex.Dispose()
    }
}

$module.ExitJson()
