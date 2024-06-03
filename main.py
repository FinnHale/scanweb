# main.py
import ctypes
import sys
import customtkinter as ctk
from gui import NetworkTool

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def start_app():
    main_app = ctk.CTk()
    app = NetworkTool(main_app)
    main_app.mainloop()

if __name__ == "__main__":
    run_as_admin()
    start_app()