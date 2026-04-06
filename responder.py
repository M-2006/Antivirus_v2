import psutil
from utils import log_action


def terminate_process(pid: int) -> bool:
    """Attempt to terminate a process by PID. Returns True on success."""
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        log_action(f"Terminated process: {name} [PID {pid}]")
        return True
    except psutil.NoSuchProcess:
        log_action(f"Process PID {pid} no longer exists.")
        return False
    except psutil.AccessDenied:
        log_action(f"Access denied terminating PID {pid}.")
        return False
    except Exception as e:
        log_action(f"Error terminating PID {pid}: {e}")
        return False


def kill_flagged(flagged_pids: list, cpu_threshold: float = 80.0) -> list:
    """
    Terminate processes from the flagged list only if their CPU is above
    cpu_threshold (extra safety check before killing).
    Returns list of PIDs that were successfully terminated.
    """
    killed = []
    for pid in flagged_pids:
        try:
            p = psutil.Process(pid)
            if p.cpu_percent(interval=0.1) > cpu_threshold:
                if terminate_process(pid):
                    killed.append(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return killed
