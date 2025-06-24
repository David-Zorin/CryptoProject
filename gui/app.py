import tkinter as tk, threading, json
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from core.secure_transfer import send, receive

# Controller is used to pair between Tk widgets and our project logic
class _Base(ttk.Frame):
    def __init__(self, master, fn):
        super().__init__(master)
        self.fn, self.inp, self.out = fn, None, None
        self._ui()

    def _ui(self):
        tk.Label(self, text="Input").grid(row=0, column=0, sticky="e")
        self.e_in = tk.Entry(self, width=40, state="readonly")
        self.e_in.grid(row=0, column=1, padx=4)
        tk.Button(self, text="Browse", command=self._sel_in).grid(row=0, column=2)

        tk.Label(self, text="Output").grid(row=1, column=0, sticky="e")
        self.e_out = tk.Entry(self, width=40, state="readonly")
        self.e_out.grid(row=1, column=1, padx=4)
        tk.Button(self, text="Browse", command=self._sel_out).grid(row=1, column=2)

        tk.Label(self, text="Pass-phrase").grid(row=2, column=0, sticky="e")
        self.e_pw = tk.Entry(self, show="•", width=22)
        self.e_pw.grid(row=2, column=1, sticky="w")

        self.pbar = ttk.Progressbar(self, length=360)
        self.pbar.grid(row=3, columnspan=3, pady=6)

        self.t_log = tk.Text(self, width=50, height=7, state="disabled")
        self.t_log.grid(row=4, columnspan=3)

        tk.Button(self, text="Run", command=self._go).grid(row=5, column=2, sticky="e")

    def _sel_in(self):
        p = filedialog.askopenfilename()
        if p:
            self.inp = Path(p)
            self._set(self.e_in, p)

    def _sel_out(self):
        p = filedialog.asksaveasfilename()
        if p:
            self.out = Path(p)
            self._set(self.e_out, p)

    def _set(self, entry, val):
        entry.config(state="normal")
        entry.delete(0, "end")
        entry.insert(0, val)
        entry.config(state="readonly")

    def _go(self):
        if not all((self.inp, self.out, self.e_pw.get())):
            messagebox.showerror("Error", "Select files and pass-phrase")
            return
        threading.Thread(target=self._run, daemon=True).start()

    # main run entry-point invoked by the GUI
    def _run(self):
        try:
            self._log("Running…")
            hdr = self.fn(str(self.inp), str(self.out), self.e_pw.get(), self._upd)
            if isinstance(hdr, bytes):
                hdr_view = json.dumps(json.loads(hdr), indent=2)
            elif isinstance(hdr, (dict, list)):
                hdr_view = json.dumps(hdr, indent=2)
            else:
                hdr_view = str(hdr)
            self._log("Finished")
            self._log(hdr_view)
        except Exception as e:
            self._log(f"Error: {e}")

    def _upd(self, f):
        self.pbar["value"] = f * 100
        self.master.update_idletasks()

    def _log(self, m):
        self.t_log.config(state="normal")
        self.t_log.insert("end", f"{m}\n")
        self.t_log.see("end")
        self.t_log.config(state="disabled")


class _Sender(_Base):
    def __init__(self, master):
        super().__init__(master, send)


class _Receiver(_Base):
    def __init__(self, master):
        super().__init__(master, receive)


def launch():
    root = tk.Tk()
    root.title("Secure File Transfer")
    nb = ttk.Notebook(root)
    nb.add(_Sender(nb), text="Sender")
    nb.add(_Receiver(nb), text="Receiver")
    nb.pack(padx=8, pady=8)
    root.resizable(False, False)
    root.mainloop()
