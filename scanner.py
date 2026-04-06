import psutil


def scan_system():
    """Scan all running processes and return enriched info."""
    processes = []

    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'status']):
        try:
            info = p.info.copy()

            # Add memory usage in MB
            try:
                mem = p.memory_info()
                info['memory_mb'] = round(mem.rss / (1024 * 1024), 2)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['memory_mb'] = 0

            # Add executable path when accessible
            try:
                info['exe'] = p.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['exe'] = ""

            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return {
        "processes": processes,
        "total": len(processes),
    }
