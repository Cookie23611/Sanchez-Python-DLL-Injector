import time
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox as mb

import pymem.process
from pymem import *

import psutil


def succes():
    mb.showinfo('Success', 'Injopted')

def inject_dll(dll_path, pid):
    # Open handle to process
    pid = int(pid)
    dll_path_bytes = bytes(dll_path, "UTF-8")
    #handle = pymem.process.process_from_id(pid)
    handle = Pymem(pid)
    pymem.process.inject_dll(handle=handle.process_handle,filepath=dll_path_bytes)
    succes()


def select_dll():
    dll_path = filedialog.askopenfilename(filetypes=[("DLL files", "*.dll")])
    return dll_path


def refresh_process_list():
    process_list =([""] + [p.name() + " " + str(p.pid) for p in psutil.process_iter() if p.name().endswith("javaw.exe") or p.name().endswith("java.exe")])
    #print(process_list[1])
    process_combo["values"] = process_list

def on_select(event):
    global process_pid
    process_pid = event.widget.get().split(" ")[1]


root = Tk()
root.title("Sanchez DLL Injector")
entry = Entry()

dll_path_label = ttk.Label(root, text="DLL Path:")
dll_path_label.grid(column=0, row=0, padx=5, pady=5, sticky="W")

dll_path_entry = ttk.Entry(root)
dll_path_entry.grid(column=1, row=0, padx=5, pady=5)

select_dll_button = ttk.Button(root, text="Select DLL", command=lambda: dll_path_entry.insert(0, select_dll()))
select_dll_button.grid(column=2, row=0, padx=5, pady=5)

process_combo = ttk.Combobox(root,values=[] , state="readonly")
process_combo.bind("<<ComboboxSelected>>", on_select)
process_combo.grid(column=1, row=1, padx=5, pady=5)

refresh_button = ttk.Button(root, text="Refresh", command=refresh_process_list)
refresh_button.grid(column=2, row=1, padx=5, pady=5)

process_label = ttk.Label(root, text="Process:")
process_label.grid(column=0, row=1, padx=5, pady=5, sticky="W")

inject_button = ttk.Button(root, text="Inject", command=lambda: inject_dll(dll_path_entry.get(), process_pid))
inject_button.grid(column=1, row=2, padx=5, pady=5)

if (__name__ == "__main__"):
    refresh_process_list()
    root.mainloop()