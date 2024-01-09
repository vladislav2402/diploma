import subprocess

def run_command(script_path):
    git_bash_executable = r"C:\Program Files\Git\bin\bash.exe"
    return subprocess.run([git_bash_executable, script_path], capture_output=True, text=True)