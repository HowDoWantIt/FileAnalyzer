import tkinter as tk
from tkinter import filedialog, scrolledtext
from analyzer.core import create_reports

def browse_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        result = create_reports(filepath)
        summary_textbox.delete(1.0, tk.END)
        summary_textbox.insert(tk.END, result['summary'])

        full_textbox.delete(1.0, tk.END)
        full_textbox.insert(tk.END, f"Full Report:\n{result['full']}")

root = tk.Tk()
root.title("File Analyzer")
root.geometry("900x700")

tk.Label(root, text="📂 Select a file to analyze:", font=("Arial", 12)).pack(pady=10)
tk.Button(root, text="Browse File", command=browse_file).pack()

tk.Label(root, text="📝 Summary Report:", font=("Arial", 11, 'bold')).pack(pady=5)
summary_textbox = scrolledtext.ScrolledText(root, height=10)
summary_textbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

tk.Label(root, text="📋 Full Report:", font=("Arial", 11, 'bold')).pack(pady=5)
full_textbox = scrolledtext.ScrolledText(root, height=15)
full_textbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

tk.Label(root, text="© Created by You | AI powered", fg="gray").pack(pady=5)

root.mainloop()
