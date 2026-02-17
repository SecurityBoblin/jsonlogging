# securitygoblin.jsonlogging

Ansible collection for logging playbook job status to structured JSON files on
**Windows** and **Linux** hosts.

| Module | Target OS | Implementation |
|--------|-----------|---------------|
| `win_job_log` | Windows | PowerShell + Ansible.Basic |
| `job_log` | Linux | Python + ansible.module_utils.basic |

Both modules produce the **same JSON schema** and accept the same parameters
(the only difference is the file-locking mechanism).  Track every job that runs
against a host — start time, end time, duration, health, task summary, and
optional SIEM / software metadata.

## Requirements

| Component | Windows | Linux |
|-----------|---------|-------|
| Ansible | 2.10+ | 2.10+ |
| OS | Server 2012 R2+ / Win 10+ | Any supported distro |
| Runtime | PowerShell 5.1+ | Python 2.7+ / 3.5+ |
| Connection | WinRM | SSH |

## Installation

```bash
# From Galaxy
ansible-galaxy collection install securitygoblin.jsonlogging

# From a tarball
ansible-galaxy collection install securitygoblin-jsonlogging-1.1.0.tar.gz

# In requirements.yml
```

```yaml
# requirements.yml
collections:
  - name: securitygoblin.jsonlogging
    version: ">=1.0.0"
```

---

## Quick Start

Add **two tasks** to any existing playbook — one at the start, one at the end.

### Windows

```yaml
- name: Log job start
  securitygoblin.jsonlogging.win_job_log:
    path: C:\ansible\status.json
    job_name: patch-windows
    state: started

# ... your existing tasks ...

- name: Log job end
  securitygoblin.jsonlogging.win_job_log:
    path: C:\ansible\status.json
    job_name: patch-windows
    state: completed
    status: ok
```

### Linux

```yaml
- name: Log job start
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: patch-linux
    state: started

# ... your existing tasks ...

- name: Log job end
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: patch-linux
    state: completed
    status: ok
```

That's it.  Timestamps, hostname, job ID, duration, and host-level aggregation
are all handled automatically.

---

## How to Log Jobs

The patterns below apply to **both** modules.  Just swap the module name and
path style for your OS:

| | Windows | Linux |
|-|---------|-------|
| Module | `securitygoblin.jsonlogging.win_job_log` | `securitygoblin.jsonlogging.job_log` |
| Path | `C:\ansible\status.json` | `/var/log/ansible/status.json` |

### Pattern 1 — Log start and success

The simplest form.  Place `state: started` before your tasks and
`state: completed` after them.

```yaml
- name: Log start
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: my-job
    state: started

- name: Do work
  ansible.builtin.shell: echo "hello"

- name: Log success
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: my-job
    state: completed
    status: ok
```

### Pattern 2 — Log start, success, and failure (recommended)

Wrap your work in a `block/rescue` so failures are also logged:

```yaml
- name: Log start
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: my-job
    state: started

- block:
    - name: Do work
      ansible.builtin.shell: echo "hello"

    - name: Log success
      securitygoblin.jsonlogging.job_log:
        path: /var/log/ansible/status.json
        job_name: my-job
        state: completed
        status: ok
        health: healthy

  rescue:
    - name: Log failure
      securitygoblin.jsonlogging.job_log:
        path: /var/log/ansible/status.json
        job_name: my-job
        state: completed
        status: failed
        health: unhealthy
```

### Pattern 3 — Full metadata with Ansible facts

Pass controller-side information using Jinja2 variables.  The module
auto-generates everything else.

#### Linux example

```yaml
- hosts: linux_servers
  vars:
    log_path: /var/log/ansible/status.json
  tasks:
    - name: Log start
      securitygoblin.jsonlogging.job_log:
        path: "{{ log_path }}"
        job_name: patch-linux
        state: started
        source:
          ansible_controller: "{{ inventory_hostname }}"
          playbook: "{{ ansible_play_name }}"
          run_id: "{{ lookup('pipe', 'date +%Y%m%d-%H%M%S') }}-{{ ansible_play_name }}"
          environment: "{{ env | default('prod') }}"
          ansible_version: "{{ ansible_version.full }}"

    - block:
        - name: Install updates
          ansible.builtin.yum:
            name: '*'
            state: latest
            security: true
          register: update_result

        - name: Log success
          securitygoblin.jsonlogging.job_log:
            path: "{{ log_path }}"
            job_name: patch-linux
            state: completed
            status: ok
            health: healthy
            summary:
              ok: 1
              changed: "{{ update_result.changed | int }}"
              failed: 0
              unreachable: 0
            host_info:
              software_installed:
                - rsyslog-8.2102
              config_applied:
                - cis-benchmark-level2
              siem:
                onboarded: true
                collector: syslog-collector-01
                syslog_running: true
                forwarding_ok: true
                last_seen: "{{ ansible_date_time.iso8601 }}"

      rescue:
        - name: Log failure
          securitygoblin.jsonlogging.job_log:
            path: "{{ log_path }}"
            job_name: patch-linux
            state: completed
            status: failed
            health: unhealthy
            summary:
              ok: 0
              changed: 0
              failed: 1
              unreachable: 0
```

#### Windows example

```yaml
- hosts: windows_servers
  vars:
    log_path: C:\ansible\status.json
  tasks:
    - name: Log start
      securitygoblin.jsonlogging.win_job_log:
        path: "{{ log_path }}"
        job_name: patch-windows
        state: started
        source:
          ansible_controller: "{{ inventory_hostname }}"
          playbook: "{{ ansible_play_name }}"
          run_id: "{{ lookup('pipe', 'date +%Y%m%d-%H%M%S') }}-{{ ansible_play_name }}"
          environment: "{{ env | default('prod') }}"
          ansible_version: "{{ ansible_version.full }}"

    - block:
        - name: Install updates
          ansible.windows.win_updates:
            category_names: [SecurityUpdates, CriticalUpdates]
            state: installed
          register: update_result

        - name: Log success
          securitygoblin.jsonlogging.win_job_log:
            path: "{{ log_path }}"
            job_name: patch-windows
            state: completed
            status: ok
            health: healthy
            summary:
              ok: 1
              changed: "{{ update_result.changed | int }}"
              failed: 0
              unreachable: 0
            host_info:
              software_installed:
                - wec-agent-2.1.0
              config_applied:
                - wec-subscription.xml
              siem:
                onboarded: true
                collector: wec-collector-01
                syslog_running: true
                forwarding_ok: true
                last_seen: "{{ ansible_date_time.iso8601 }}"

      rescue:
        - name: Log failure
          securitygoblin.jsonlogging.win_job_log:
            path: "{{ log_path }}"
            job_name: patch-windows
            state: completed
            status: failed
            health: unhealthy
            summary:
              ok: 0
              changed: 0
              failed: 1
              unreachable: 0
```

---

## Module Reference

### Shared parameters

Both `win_job_log` and `job_log` accept the same parameters:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `path` | path | **yes** | | Absolute path to the JSON log file |
| `job_name` | str | **yes** | | Unique job name (upsert key) |
| `state` | str | **yes** | | `started` or `completed` |
| `status` | str | no | `ok` | `ok`, `failed`, `unreachable` |
| `health` | str | no | `healthy` | `healthy`, `degraded`, `unhealthy` |
| `source` | dict | no | `{}` | Controller/playbook metadata (see below) |
| `summary` | dict | no | `{}` | Task statistics (see below) |
| `host_info` | dict | no | `{}` | Host-level information (see below) |
| `job_id` | str | no | auto | Custom job ID; auto-generated as `host-HOSTNAME-NNNNN` if omitted |
| `create_directory` | bool | no | `true` | Create parent directories if missing |

### Platform-specific parameters

| Parameter | Module | Type | Default | Description |
|-----------|--------|------|---------|-------------|
| `mutex_timeout_ms` | `win_job_log` | int | `30000` | Windows Mutex lock timeout (ms) |
| `lock_timeout_sec` | `job_log` | int | `30` | Linux flock timeout (seconds) |

### `source` sub-parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ansible_controller` | str | `unknown` | Controller hostname |
| `playbook` | str | `unknown` | Playbook name |
| `run_id` | str | auto | Unique run ID; auto-generated from timestamp if empty |
| `environment` | str | `unknown` | Environment name (`prod`, `staging`, `dev`) |
| `ansible_version` | str | `unknown` | Ansible version string |

### `summary` sub-parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ok` | int | `0` | Successful tasks |
| `changed` | int | `0` | Tasks that made changes |
| `failed` | int | `0` | Failed tasks |
| `unreachable` | int | `0` | Unreachable targets |

### `host_info` sub-parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `software_installed` | list(str) | `[]` | Software installed on host |
| `config_applied` | list(str) | `[]` | Configurations applied |
| `siem.onboarded` | bool | `false` | SIEM onboarding status |
| `siem.collector` | str | `""` | SIEM collector hostname |
| `siem.syslog_running` | bool | `false` | Syslog forwarding active |
| `siem.forwarding_ok` | bool | `false` | Forwarding health |
| `siem.last_seen` | str | `""` | Last SIEM heartbeat (ISO 8601) |

### What gets auto-generated

These fields are set automatically — you don't need to provide them:

| Field | Source | When |
|-------|--------|------|
| `generated_at` | Current UTC time | Every call |
| `host.name` | Hostname (`$env:COMPUTERNAME` / `socket.gethostname()`) | File creation |
| `started_at` | Current UTC time | `state: started` |
| `finished_at` | Current UTC time | `state: completed` |
| `duration_sec` | `finished_at - started_at` | `state: completed` |
| `job_id` | `host-HOSTNAME-NNNNN` | Job creation (if not provided) |
| `run_id` | `YYYYMMDD-HHMMSS-jobname` | If not in `source` |
| `host.status` | Aggregated from all jobs | Every call |
| `host.health` | Aggregated from all jobs | Every call |
| `maintenance_window.*` | Mirrors job start/end | Automatic |

### Return values

| Key | Type | Description |
|-----|------|-------------|
| `changed` | bool | Always `true` when file is written |
| `path` | str | Path to the log file |
| `job_name` | str | Job name that was logged |
| `state` | str | State that was recorded |
| `job_id` | str | ID of the job entry |

---

## JSON Schema Reference

Both modules produce the same schema (version `1.0`):

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-02-06T14:32:10Z",
  "source": {
    "ansible_controller": "aap-prod-01",
    "playbook": "site.yml",
    "run_id": "aap-20260206-143210-abc123",
    "environment": "prod",
    "ansible_version": "2.14.12"
  },
  "jobs": [
    {
      "job_name": "patch-windows",
      "job_id": "host-srv-001-12345",
      "status": "ok",
      "started_at": "2026-02-06T13:00:00Z",
      "finished_at": "2026-02-06T13:15:00Z",
      "duration_sec": 900,
      "health": "healthy",
      "summary": {
        "ok": 1,
        "changed": 0,
        "failed": 0,
        "unreachable": 0
      },
      "maintenance_window": {
        "started_at": "2026-02-06T13:00:00Z",
        "ended_at": "2026-02-06T13:15:00Z",
        "ended": true
      }
    }
  ],
  "host": {
    "name": "srv-001",
    "status": "ok",
    "health": "healthy",
    "software_installed": ["wec-agent-2.1.0"],
    "config_applied": ["wec-subscription.xml"],
    "siem": {
      "onboarded": true,
      "collector": "wec-collector-01",
      "syslog_running": true,
      "forwarding_ok": true,
      "last_seen": "2026-02-06T13:14:00Z"
    }
  }
}
```

### Field reference

| Path | Type | Description |
|------|------|-------------|
| `schema_version` | str | Always `"1.0"` |
| `generated_at` | str | ISO 8601 UTC — last time file was written |
| `source.ansible_controller` | str | Controller node identifier |
| `source.playbook` | str | Playbook name |
| `source.run_id` | str | Unique run identifier |
| `source.environment` | str | Environment name |
| `source.ansible_version` | str | Ansible version |
| `jobs[].job_name` | str | Unique job name |
| `jobs[].job_id` | str | Auto-generated or custom ID |
| `jobs[].status` | str | `running`, `ok`, `failed`, `unreachable` |
| `jobs[].started_at` | str | ISO 8601 UTC start time |
| `jobs[].finished_at` | str | ISO 8601 UTC end time |
| `jobs[].duration_sec` | int | Duration in seconds |
| `jobs[].health` | str | `healthy`, `degraded`, `unhealthy` |
| `jobs[].summary.ok` | int | OK task count |
| `jobs[].summary.changed` | int | Changed task count |
| `jobs[].summary.failed` | int | Failed task count |
| `jobs[].summary.unreachable` | int | Unreachable count |
| `jobs[].maintenance_window.started_at` | str | Maintenance window start |
| `jobs[].maintenance_window.ended_at` | str | Maintenance window end |
| `jobs[].maintenance_window.ended` | bool | Whether window has closed |
| `host.name` | str | Hostname |
| `host.status` | str | Aggregated: `ok`, `running`, `failed` |
| `host.health` | str | Aggregated: `healthy`, `degraded`, `unhealthy` |
| `host.software_installed` | list | Software packages |
| `host.config_applied` | list | Applied configurations |
| `host.siem.onboarded` | bool | SIEM onboarding flag |
| `host.siem.collector` | str | Collector hostname |
| `host.siem.syslog_running` | bool | Syslog active |
| `host.siem.forwarding_ok` | bool | Forwarding health |
| `host.siem.last_seen` | str | Last heartbeat timestamp |

---

## Advanced Examples

### Multiple jobs in a single playbook (Windows)

```yaml
- hosts: windows_servers
  vars:
    log_path: C:\ansible\status.json
    src: &src
      ansible_controller: "{{ inventory_hostname }}"
      playbook: "{{ ansible_play_name }}"
      environment: "{{ env | default('prod') }}"
      ansible_version: "{{ ansible_version.full }}"
  tasks:
    # ── Job 1: Patching ──
    - name: "[patch] Start"
      securitygoblin.jsonlogging.win_job_log:
        path: "{{ log_path }}"
        job_name: patch-windows
        state: started
        source: *src

    - name: "[patch] Install updates"
      ansible.windows.win_updates:
        category_names: [SecurityUpdates]
        state: installed

    - name: "[patch] Complete"
      securitygoblin.jsonlogging.win_job_log:
        path: "{{ log_path }}"
        job_name: patch-windows
        state: completed
        status: ok

    # ── Job 2: Compliance scan ──
    - name: "[compliance] Start"
      securitygoblin.jsonlogging.win_job_log:
        path: "{{ log_path }}"
        job_name: compliance-scan
        state: started
        source: *src

    - name: "[compliance] Run scan"
      ansible.windows.win_shell: C:\tools\compliance-scan.exe

    - name: "[compliance] Complete"
      securitygoblin.jsonlogging.win_job_log:
        path: "{{ log_path }}"
        job_name: compliance-scan
        state: completed
        status: ok
```

### Multiple jobs in a single playbook (Linux)

```yaml
- hosts: linux_servers
  vars:
    log_path: /var/log/ansible/status.json
    src: &src
      ansible_controller: "{{ inventory_hostname }}"
      playbook: "{{ ansible_play_name }}"
      environment: "{{ env | default('prod') }}"
      ansible_version: "{{ ansible_version.full }}"
  tasks:
    # ── Job 1: Patching ──
    - name: "[patch] Start"
      securitygoblin.jsonlogging.job_log:
        path: "{{ log_path }}"
        job_name: patch-linux
        state: started
        source: *src

    - name: "[patch] Install updates"
      ansible.builtin.yum:
        name: '*'
        state: latest
        security: true

    - name: "[patch] Complete"
      securitygoblin.jsonlogging.job_log:
        path: "{{ log_path }}"
        job_name: patch-linux
        state: completed
        status: ok

    # ── Job 2: Compliance scan ──
    - name: "[compliance] Start"
      securitygoblin.jsonlogging.job_log:
        path: "{{ log_path }}"
        job_name: compliance-scan
        state: started
        source: *src

    - name: "[compliance] Run scan"
      ansible.builtin.shell: /opt/tools/compliance-scan

    - name: "[compliance] Complete"
      securitygoblin.jsonlogging.job_log:
        path: "{{ log_path }}"
        job_name: compliance-scan
        state: completed
        status: ok
```

### Custom job IDs

```yaml
# Windows
- name: Log with custom ID
  securitygoblin.jsonlogging.win_job_log:
    path: C:\ansible\status.json
    job_name: patch-windows
    job_id: "PATCH-{{ ansible_date_time.date }}-001"
    state: started

# Linux
- name: Log with custom ID
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: patch-linux
    job_id: "PATCH-{{ ansible_date_time.date }}-001"
    state: started
```

### Check mode (dry run)

```yaml
- name: Dry run
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: test-job
    state: started
  check_mode: true
```

---

## Troubleshooting

### "Failed to acquire file lock" (Windows)

Another process is writing to the same file.  Increase the timeout:

```yaml
securitygoblin.jsonlogging.win_job_log:
  mutex_timeout_ms: 60000   # 60 seconds
```

### "Failed to acquire file lock" (Linux)

Same issue on Linux.  Increase the timeout:

```yaml
securitygoblin.jsonlogging.job_log:
  lock_timeout_sec: 60   # 60 seconds
```

### "Failed to parse existing JSON file"

The file is corrupted.  Delete it and let the module recreate it, or validate
it manually:

```powershell
# Windows
Get-Content C:\ansible\status.json | ConvertFrom-Json
```

```bash
# Linux
python3 -m json.tool /var/log/ansible/status.json
```

### Module not found

```bash
# Verify installation
ansible-galaxy collection list | grep securitygoblin

# Reinstall
ansible-galaxy collection install securitygoblin.jsonlogging --force
```

### Permission denied

Ensure the Ansible user has write access to the target directory:

```yaml
# Windows
- name: Ensure log directory exists
  ansible.windows.win_file:
    path: C:\ansible
    state: directory

# Linux
- name: Ensure log directory exists
  ansible.builtin.file:
    path: /var/log/ansible
    state: directory
    mode: "0755"
```

## License

MIT
