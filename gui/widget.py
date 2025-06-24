import tkinter as tk
from tkinter import filedialog, ttk, messagebox

# Tk.Frame subclass holding all GUI controls
class CryptoGUI(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master)
        self.controller = controller
        self._build()

    # build and lay out the widgets (grid geometry)
    def _build(self):
        self.grid(padx=10, pady=10)
        # ------------ file selectors -----------------
        tk.Label(self, text="Input file:").grid(row=0, column=0, sticky='e')
        self.in_entry = tk.Entry(self, width=38, state='readonly')
        self.in_entry.grid(row=0, column=1, padx=5)
        tk.Button(self, text="Select…",
                  command=self.controller.select_input).grid(row=0, column=2)

        tk.Label(self, text="Output file:").grid(row=1, column=0, sticky='e')
        self.out_entry = tk.Entry(self, width=38, state='readonly')
        self.out_entry.grid(row=1, column=1, padx=5)
        tk.Button(self, text="Select…",
                  command=self.controller.select_output).grid(row=1, column=2)

        ttk.Separator(self, orient='horizontal').grid(row=2, columnspan=3,
                                                      sticky='ew', pady=8)
        # ------------ options ------------------------
        self.op_var = tk.StringVar(value='Encrypt')
        tk.Label(self, text="Operation:").grid(row=3, column=0, sticky='w')
        for i, txt in enumerate(("Encrypt", "Decrypt")):
            tk.Radiobutton(self, text=txt, variable=self.op_var,
                           value=txt).grid(row=4 + i, column=0, sticky='w')


        tk.Label(self, text="Key / Password:").grid(row=3, column=2,
                                                    sticky='w')
        self.key_entry = tk.Entry(self, show='•', width=18)
        self.key_entry.grid(row=4, column=2, rowspan=2, sticky='n')

        ttk.Separator(self, orient='horizontal').grid(row=6, columnspan=3,
                                                      sticky='ew', pady=8)
        # ------------- run bar -----------------------
        self.status = tk.Text(self, height=4, width=52, state='disabled')
        self.status.grid(row=7, column=0, columnspan=2)
        self.run_btn = tk.Button(self, text="Run",
                                 command=self.controller.run)
        self.run_btn.grid(row=7, column=2, sticky='n')
        self.pbar = ttk.Progressbar(self, length=400)
        self.pbar.grid(row=8, columnspan=3, pady=4)
