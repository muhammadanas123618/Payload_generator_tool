import tkinter as tk
from tkinter import ttk
from modules.xss import generate_xss_payloads
from modules.sqli import generate_sqli_payloads
from modules.cmdi import generate_cmdi_payloads

def run_gui():
    def generate():
        module = module_var.get().lower()
        encoding = encode_var.get() if encode_var.get() != "None" else None
        obfuscate = obfuscate_var.get()
        bypass = bypass_var.get()

        if module == "xss":
            payloads = generate_xss_payloads(encoding, obfuscate, bypass)
        elif module == "sqli":
            payloads = generate_sqli_payloads(encoding, obfuscate, bypass)
        elif module == "cmdi":
            payloads = generate_cmdi_payloads(encoding, obfuscate, bypass)
        else:
            payloads = []

        output_box.delete("1.0", tk.END)

        for p in payloads:
            formatted = f"[{p['type']}] {p['payload']}\n"
            output_box.insert(tk.END, formatted + "\n")

        status_label.config(text=f"Generated {len(payloads)} payloads")

    # GUI Window
    root = tk.Tk()
    root.title("Payload Generator GUI")
    root.geometry("800x600")
    root.resizable(False, False)

    # Style
    style = ttk.Style()
    style.configure("TLabel", padding=5)
    style.configure("TButton", padding=5)
    style.configure("TCheckbutton", padding=5)

    # Variables
    module_var = tk.StringVar(value="XSS")
    encode_var = tk.StringVar(value="None")
    obfuscate_var = tk.BooleanVar()
    bypass_var = tk.BooleanVar()

    # Module Selector
    ttk.Label(root, text="Module").grid(row=0, column=0, sticky="w", padx=10, pady=10)
    ttk.Combobox(root, textvariable=module_var, values=["XSS", "SQLi", "CMDi"], state="readonly").grid(row=0, column=1, sticky="w")

    # Encoding Selector
    ttk.Label(root, text="Encoding").grid(row=1, column=0, sticky="w", padx=10)
    ttk.Combobox(root, textvariable=encode_var, values=["None", "base64", "url", "hex", "unicode"], state="readonly").grid(row=1, column=1, sticky="w")

    # Obfuscation + Bypass Checkboxes
    ttk.Checkbutton(root, text="Obfuscate", variable=obfuscate_var).grid(row=0, column=2, padx=10)
    ttk.Checkbutton(root, text="WAF Bypass", variable=bypass_var).grid(row=1, column=2, padx=10)

    # Generate Button
    ttk.Button(root, text="Generate", command=generate).grid(row=0, column=3, rowspan=2, padx=10)

    # Output Box (Scrollable)
    output_frame = ttk.Frame(root)
    output_frame.grid(row=2, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")

    scrollbar = tk.Scrollbar(output_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    output_box = tk.Text(output_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set, font=("Courier", 10))
    output_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=output_box.yview)

    # Status
    status_label = ttk.Label(root, text="Ready")
    status_label.grid(row=3, column=0, columnspan=4, pady=5, sticky="w", padx=10)

    root.mainloop()
