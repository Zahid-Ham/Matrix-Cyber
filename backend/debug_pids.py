import psutil

for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
    if proc.info['name'] == 'python.exe':
        print(f"PID: {proc.info['pid']}, Cmd: {proc.info['cmdline']}")
