import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64
import os

class FileProtectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor & Decryptor")
        self.root.geometry("600x450")
        self.root.resizable(False, False)

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Helvetica', 10), padding=5)
        style.configure('TLabel', font=('Helvetica', 10))
        style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))

        # Create Tabs
        self.tab_control = ttk.Notebook(root)
        
        self.tab_protect = ttk.Frame(self.tab_control)
        self.tab_restore = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.tab_protect, text='   Protect (Encode)   ')
        self.tab_control.add(self.tab_restore, text='   Restore (Decode)   ')
        
        self.tab_control.pack(expand=1, fill="both")

        # --- SETUP TAB 1: PROTECT ---
        self.setup_protect_tab()

        # --- SETUP TAB 2: RESTORE ---
        self.setup_restore_tab()

    def setup_protect_tab(self):
        frame = ttk.Frame(self.tab_protect, padding=20)
        frame.pack(fill="both", expand=True)

        # Instructions
        lbl_instruction = ttk.Label(
            frame, 
            text="Step 1: Select the document to encrypt.\nThis will result in an encrypted text file.\n",
            justify="left"
        )
        lbl_instruction.pack(pady=(0, 20), anchor="w")

        # File Selection
        lbl_select = ttk.Label(frame, text="Selected File:", style='Header.TLabel')
        lbl_select.pack(anchor="w")

        self.protect_file_path = tk.StringVar()
        entry_protect = ttk.Entry(frame, textvariable=self.protect_file_path, width=50, state='readonly')
        entry_protect.pack(fill="x", pady=5)

        btn_browse_protect = ttk.Button(frame, text="Browse Document...", command=self.browse_file_to_protect)
        btn_browse_protect.pack(anchor="e", pady=5)

        # Separator
        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=20)

        # Action Button
        btn_process = ttk.Button(frame, text="Generate Text File", command=self.process_encryption)
        btn_process.pack(fill="x", pady=10)

        self.lbl_status_protect = ttk.Label(frame, text="Ready", foreground="gray")
        self.lbl_status_protect.pack(pady=5)

    def setup_restore_tab(self):
        frame = ttk.Frame(self.tab_restore, padding=20)
        frame.pack(fill="both", expand=True)

        # Instructions
        lbl_instruction = ttk.Label(
            frame, 
            text="Step 2: Select the text file.\n"
                 "This will restore it back to the original Word/PDF/Image.",
            justify="left"
        )
        lbl_instruction.pack(pady=(0, 20), anchor="w")

        # File Selection
        lbl_select = ttk.Label(frame, text="Selected Text File:", style='Header.TLabel')
        lbl_select.pack(anchor="w")

        self.restore_file_path = tk.StringVar()
        entry_restore = ttk.Entry(frame, textvariable=self.restore_file_path, width=50, state='readonly')
        entry_restore.pack(fill="x", pady=5)

        btn_browse_restore = ttk.Button(frame, text="Browse Text File...", command=self.browse_file_to_restore)
        btn_browse_restore.pack(anchor="e", pady=5)

        # Separator
        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=20)

        # Action Button
        btn_process = ttk.Button(frame, text="Restore Original Document", command=self.process_decryption)
        btn_process.pack(fill="x", pady=10)

        self.lbl_status_restore = ttk.Label(frame, text="Ready", foreground="gray")
        self.lbl_status_restore.pack(pady=5)

    # --- LOGIC ---

    def browse_file_to_protect(self):
        filename = filedialog.askopenfilename(title="Select Document")
        if filename:
            self.protect_file_path.set(filename)
            self.lbl_status_protect.config(text="File selected.", foreground="black")

    def browse_file_to_restore(self):
        filename = filedialog.askopenfilename(title="Select Encoded Text File", filetypes=[("Text Files", "*.txt")])
        if filename:
            self.restore_file_path.set(filename)
            self.lbl_status_restore.config(text="File selected.", foreground="black")

    def process_encryption(self):
        input_path = self.protect_file_path.get()
        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("Error", "Please select a valid file first.")
            return

        try:
            # 1. Read binary data
            with open(input_path, "rb") as f:
                binary_data = f.read()

            # 2. Encode to Base64
            b64_data = base64.b64encode(binary_data).decode('utf-8')

            # 3. Create output filename
            original_filename = os.path.basename(input_path)
            output_filename = f"{os.path.splitext(original_filename)[0]}__ready.txt"
            
            # Save dialog
            save_path = filedialog.asksaveasfilename(
                initialfile=output_filename,
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt")],
                title="Save  Content As"
            )

            if not save_path:
                return

            # 4. Write with Header (Metadata for automatic restoration)
            with open(save_path, "w") as f:
                f.write(f"# ORIGINAL_FILENAME: {original_filename}\n")
                f.write("# INSTRUCTIONS: This is a Base64 encoded file. Use the 'Restore' tab in the app to open it.\n")
                f.write("# ------------------------------------------------------------\n")
                f.write(b64_data)

            self.lbl_status_protect.config(text=f"Success! Saved to {os.path.basename(save_path)}", foreground="green")
            messagebox.showinfo("Success", 
                f"File converted successfully!\n\n"
                f"1. Open '{os.path.basename(save_path)}'\n"
            )

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def process_decryption(self):
        input_path = self.restore_file_path.get()
        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("Error", "Please select the text file first.")
            return

        try:
            # 1. Read the text file
            with open(input_path, "r") as f:
                lines = f.readlines()

            # 2. Parse Header to find original filename
            original_name = "restored_file"
            start_line = 0
            
            for i, line in enumerate(lines):
                if line.startswith("# ORIGINAL_FILENAME:"):
                    original_name = line.split(":", 1)[1].strip()
                elif line.startswith("#") or line.strip() == "":
                    # Skip comments and empty header lines
                    continue
                else:
                    # Found the start of data
                    start_line = i
                    break

            # 3. Reassemble the Base64 string
            encoded_data = "".join(lines[start_line:])

            if not encoded_data.strip():
                messagebox.showerror("Error", "No data found in file.")
                return

            # 4. Decode
            binary_data = base64.b64decode(encoded_data)

            # 5. Save Dialog
            save_path = filedialog.asksaveasfilename(
                initialfile=original_name,
                title="Save Restored Document As"
            )

            if not save_path:
                return

            # 6. Write binary file
            with open(save_path, "wb") as f:
                f.write(binary_data)

            self.lbl_status_restore.config(text=f"Restored: {os.path.basename(save_path)}", foreground="green")
            messagebox.showinfo("Success", f"File restored successfully as:\n{save_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore file.\nDetails: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileProtectorApp(root)
    root.mainloop()
