import struct
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

class DATEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("Pokemon Scarlet / Violet DAT Text Editor")
        self.root.geometry("800x600")

        # File / editor state
        self.files = []
        self.current_file_index = -1
        self.current_lines = []
        self.search_results = []
        self.current_search_index = -1

        # Compare state
        self.compare_window = None
        self.compare_folder = None
        self.compare_lines = []
        self.compare_mode = False

        # Scroll sync flag
        self._syncing = False

        self.create_widgets()
        self.add_search_functionality()

    def create_widgets(self):
        # Top frame for controls
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(top_frame, text="Open Folder", command=self.open_folder).pack(side=tk.LEFT)
        self.save_btn = ttk.Button(top_frame, text="Save", command=self.save_file, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT)
        self.export_btn = ttk.Button(top_frame, text="Export TXT", command=self.export_txt, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT)
        self.import_btn = ttk.Button(top_frame, text="Import TXT", command=self.import_txt, state=tk.DISABLED)
        self.import_btn.pack(side=tk.LEFT)

        # Compare button
        self.compare_btn = ttk.Button(top_frame, text="Compare", command=self.open_compare_window, state=tk.NORMAL)
        self.compare_btn.pack(side=tk.LEFT, padx=5)

        self.path_label = ttk.Label(top_frame, text="No folder loaded")
        self.path_label.pack(side=tk.LEFT, padx=10)

        # File selection
        file_frame = ttk.Frame(self.root)
        file_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(file_frame, text="File:").pack(side=tk.LEFT)
        self.file_combo = ttk.Combobox(file_frame, state="readonly", width=50)
        self.file_combo.pack(side=tk.LEFT, padx=5)
        self.file_combo.bind('<<ComboboxSelected>>', self.on_file_select)
        # Add keyboard navigation
        self.file_combo.bind('<Down>', self.on_arrow_key)
        self.file_combo.bind('<Up>', self.on_arrow_key)                           

        # Text editor 
        editor_frame = ttk.Frame(self.root)
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(editor_frame, text="Text Lines:").pack(anchor=tk.W)

        # Create a frame for the table and scrollbars
        table_frame = ttk.Frame(editor_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)

        # Create treeview as a table
        self.tree = ttk.Treeview(table_frame, columns=('index', 'text'), show='headings', selectmode='browse')
        self.tree.heading('index', text='Line')
        self.tree.column('index', width=50, minwidth=50, anchor='center', stretch=False)
        self.tree.heading('text', text='Text')
        self.tree.column('text', minwidth=400, anchor='center', stretch=True)

        # Add scrollbars
        self.v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.on_scrollbar)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=self.v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        # Grid layout for proper scrolling
        self.tree.grid(row=0, column=0, sticky='nsew')
        self.v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Line editing buttons
        button_frame = ttk.Frame(editor_frame)
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Add Line", command=self.add_line).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Remove Line", command=self.remove_line).pack(side=tk.LEFT)

        # Bind double-click to edit
        self.tree.bind('<Double-1>', self.on_double_click)
        # Bind treeview selection to update current_lines
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        # Mousewheel sync
        self.tree.bind('<MouseWheel>', self.on_main_mouse_wheel)      # Windows / Mac
        self.tree.bind('<Button-4>', self.on_main_mouse_wheel)        # Linux scroll up
        self.tree.bind('<Button-5>', self.on_main_mouse_wheel)        # Linux scroll down

        # Configure highlight tags
        self.tree.tag_configure("search_highlight", background="yellow")
        self.tree.tag_configure("diff_main", background="lightcoral")
        self.tree.tag_configure("missing_in_compare", background="lightcoral")
        self.tree.tag_configure("extra_in_compare", background="lightgreen")

    def on_arrow_key(self, event):
        # Handle up/down arrow keys in file combobox
        current_index = self.file_combo.current()
        if event.keysym == 'Down' and current_index < len(self.files) - 1:
            self.file_combo.current(current_index + 1)
            self.load_file(current_index + 1)
        elif event.keysym == 'Up' and current_index > 0:
            self.file_combo.current(current_index - 1)
            self.load_file(current_index - 1)
        return "break"  # Prevent default behavior
        
    def add_search_functionality(self):
        # Search bar and navigation
        search_frame = ttk.Frame(self.root)
        search_frame.pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind('<KeyRelease>', self.search_text)

        ttk.Button(search_frame, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=5)

        # Navigation buttons for search results
        nav_frame = ttk.Frame(search_frame)
        nav_frame.pack(side=tk.LEFT, padx=10)

        ttk.Button(nav_frame, text="↑", width=2, command=self.prev_search_result).pack(side=tk.LEFT)
        ttk.Button(nav_frame, text="↓", width=2, command=self.next_search_result).pack(side=tk.LEFT)

        self.search_status = ttk.Label(search_frame, text="")
        self.search_status.pack(side=tk.LEFT, padx=5)

    def search_text(self, event=None):
        # Search the treeview rows for the term and collect matching items
        search_term = self.search_var.get().lower()
        self.search_results = []

        if not search_term:
            self.clear_search_highlight()
            self.search_status.config(text="")
            return

        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if len(values) >= 2 and search_term in values[1].lower():
                self.search_results.append(item)

        if self.search_results:
            self.current_search_index = 0
            self.highlight_search_result()
            self.search_status.config(text=f"{self.current_search_index + 1}/{len(self.search_results)}")
        else:
            self.search_status.config(text="No results")
            self.current_search_index = -1

    def clear_search(self):
        # Clear search state and highlights
        self.search_var.set("")
        self.clear_search_highlight()
        self.search_status.config(text="")
        self.search_results = []
        self.current_search_index = -1

    def clear_search_highlight(self):
        # Remove tags from all items
        for item in self.tree.get_children():
            current_tags = list(self.tree.item(item, 'tags'))
            if "search_highlight" in current_tags:
                current_tags.remove("search_highlight")
                self.tree.item(item, tags=tuple(current_tags))

    def highlight_search_result(self):
        # Highlight current search hit and ensure it's visible
        self.clear_search_highlight()
        if self.current_search_index >= 0 and self.current_search_index < len(self.search_results):
            item = self.search_results[self.current_search_index]
            tags = list(self.tree.item(item, 'tags'))
            if "search_highlight" not in tags:
                tags.append("search_highlight")
            self.tree.item(item, tags=tuple(tags))
            self.tree.see(item)
            self.tree.selection_set(item)

    def prev_search_result(self):
        if self.search_results:
            self.current_search_index = (self.current_search_index - 1) % len(self.search_results)
            self.highlight_search_result()
            self.search_status.config(text=f"{self.current_search_index + 1}/{len(self.search_results)}")

    def next_search_result(self):
        if self.search_results:
            self.current_search_index = (self.current_search_index + 1) % len(self.search_results)
            self.highlight_search_result()
            self.search_status.config(text=f"{self.current_search_index + 1}/{len(self.search_results)}")

    def open_folder(self):
        # Ask user to pick a folder containing .dat files and populate combobox
        folder_path = filedialog.askdirectory(title="Select Folder with .dat files")
        if not folder_path:
            return

        self.files = [os.path.join(folder_path, f) for f in os.listdir(folder_path)
                     if f.endswith('.dat') and os.path.isfile(os.path.join(folder_path, f))]

        if not self.files:
            messagebox.showerror("Error", "No .dat files found in selected folder")
            return

        self.path_label.config(text=folder_path)
        self.file_combo['values'] = [os.path.basename(f) for f in self.files]
        if self.files:
            self.file_combo.current(0)
            self.load_file(0)

        # Enable buttons
        self.save_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL)
        self.import_btn.config(state=tk.NORMAL)
        self.compare_btn.config(state=tk.NORMAL)  # enable compare

    def load_file(self, index):
        # Load .dat file into current_lines and refresh display
        self.current_file_index = index
        file_path = self.files[index]

        try:
            self.current_lines = self.get_strings_from_dat(file_path)
            self.update_text_display()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
            return

        # If compare window is open and has a compare folder set, attempt to open matching file
        if self.compare_window and self.compare_window.winfo_exists():
            # If compare folder is set in compare_window, try to load same filename
            cmp_folder = self.compare_window.compare_folder
            if cmp_folder:
                file_name = os.path.basename(file_path)
                cmp_path = os.path.join(cmp_folder, file_name)
                if os.path.exists(cmp_path):
                    try:
                        self.compare_window.load_file_by_path(cmp_path)
                        # After loading compare file, highlight differences in both trees
                        self.highlight_differences()
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to load compare file: {str(e)}")
                else:
                    # File not found in compare folder — show English error
                    messagebox.showerror("Error", f"File '{file_name}' not found in compare folder")

    def on_file_select(self, event):
        # User selected a different file from combobox
        self.load_file(self.file_combo.current())

    def update_text_display(self):
        # Refresh treeview content from current_lines
        # Clear previous tags first
        for item in self.tree.get_children():
            self.tree.delete(item)

        for i, line in enumerate(self.current_lines):
            self.tree.insert('', 'end', values=(i, line))

    def on_double_click(self, event):
        # Edit the selected row on double-click
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            self.edit_line(item)

    def on_tree_select(self, event):
        # Update current_lines with any changes from the treeview
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if len(values) >= 2:
                try:
                    line_index = int(values[0])
                except Exception:
                    continue
                new_text = values[1]
                if line_index < len(self.current_lines) and self.current_lines[line_index] != new_text:
                    self.current_lines[line_index] = new_text

    def edit_line(self, item):
        # Get current values
        values = self.tree.item(item, 'values')
        line_index = int(values[0])
        current_text = values[1]

        # Create edit window
        edit_dialog = tk.Toplevel(self.root)
        edit_dialog.title(f"Edit Line {line_index}")
        edit_dialog.geometry("500x300")
        edit_dialog.transient(self.root)
        edit_dialog.grab_set()

        # Configure grid for proper expansion
        edit_dialog.grid_rowconfigure(0, weight=1)
        edit_dialog.grid_columnconfigure(0, weight=1)

        # Text area
        text_area = ScrolledText(edit_dialog, wrap=tk.WORD)
        text_area.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        text_area.insert('1.0', current_text)

        # Button frame
        button_frame = ttk.Frame(edit_dialog)
        button_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        def save_changes():
            new_text = text_area.get('1.0', tk.END).strip()
            self.current_lines[line_index] = new_text
            self.tree.item(item, values=(line_index, new_text))
            # If compare is active, recompute diffs
            if self.compare_window and self.compare_window.winfo_exists():
                self.highlight_differences()
            edit_dialog.destroy()

        # Functions for copy and paste
        def copy_text():
            text_content = text_area.get("1.0", tk.END)
            root.clipboard_clear()
            root.clipboard_append(text_content)
            root.update()

        def paste_text():
            text_content = root.clipboard_get()
            text_area.delete("1.0", tk.END)
            text_area.event_generate("<<Paste>>")

        copy_btn = ttk.Button(button_frame, text="Copy", command=copy_text)
        copy_btn.pack(side=tk.LEFT, padx=5)
        paste_btn = ttk.Button(button_frame, text="Paste", command=paste_text)
        paste_btn.pack(side=tk.LEFT, padx=5)


        ttk.Frame(button_frame).pack(side=tk.LEFT, expand=True, fill=tk.X)

        # Save and Cancel buttons
        cancel_btn = ttk.Button(button_frame, text="Cancel", command=edit_dialog.destroy)
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        save_btn = ttk.Button(button_frame, text="Save", command=save_changes)
        save_btn.pack(side=tk.RIGHT, padx=5)

    def add_line(self):
        # Add new line at the end
        self.current_lines.append("New line")
        self.update_text_display()

    def remove_line(self):
        # Remove the currently selected line
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.tree.item(item, 'values')
        line_index = int(values[0])

        if messagebox.askyesno("Confirm", f"Delete line {line_index}?"):
            del self.current_lines[line_index]
            self.update_text_display()

    def save_file(self):
        # Save edited lines back into the .dat file (re-encrypt and write)
        if self.current_file_index < 0:
            return

        try:
            # Update current_lines from treeview
            self.on_tree_select(None)

            file_path = self.files[self.current_file_index]
            encrypted_data = self.get_bytes_for_file(self.current_lines)

            with open(file_path, 'wb') as f:
                f.write(encrypted_data)

            messagebox.showinfo("Success", "File saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def export_txt(self):
        # Export current text to a .txt file (simple header + all lines)
        if not self.files or self.current_file_index < 0:
            return

        save_path = filedialog.asksaveasfilename(
            title="Export Text File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )

        if not save_path:
            return

        try:
            # Update current_lines from treeview
            self.on_tree_select(None)

            with open(save_path, 'w', encoding='utf-8') as f:
                file_path = self.files[self.current_file_index]

                f.write("~~~~~~~~~~~~~~~\n")
                f.write(f"Text File: {os.path.basename(file_path)}\n")
                f.write("~~~~~~~~~~~~~~~\n")

                for line in self.current_lines:
                    f.write(line + '\n')

            messagebox.showinfo("Success", "Text exported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export text: {str(e)}")

    def import_txt(self):
        # Import a text file previously exported by this tool (parsing out header)
        if self.current_file_index < 0:
            return

        file_path = filedialog.askopenfilename(
            title="Import Text File",
            filetypes=[("Text files", "*.txt")]
        )

        if not file_path:
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Find the start of the text content (after the header)
            content_start = 0
            for i, line in enumerate(lines):
                if "~~~~~~~~~~~~~~~" in line and i > 0:
                    content_start = i + 1
                    break

            # Extract the text lines
            imported_lines = []
            for line in lines[content_start:]:
                line = line.strip()
                if line and not line.startswith("~~~~~~~~~~~~~~~"):
                    imported_lines.append(line)

            if not imported_lines:
                messagebox.showerror("Error", "No valid text found in the selected file")
                return

            # Update the current lines
            self.current_lines = imported_lines
            self.update_text_display()

            messagebox.showinfo("Success", "Text imported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import text: {str(e)}")

    # DAT file handling methods
    def decrypt_u16(self, data, offset, key):
        # Decrypt a 16-bit value (two bytes) from data at offset using rolling key
        val = struct.unpack_from('<H', data, offset)[0] ^ key
        offset += 2
        key = ((key << 3) | (key >> 13)) & 0xFFFF
        return val, offset, key

    def decrypt_variable(self, data, offset, key):
        # Decrypt special variable sequences inside text entries
        result = ""
        # Read length
        length, offset, key = self.decrypt_u16(data, offset, key)
        # Read variable type
        var_type, offset, key = self.decrypt_u16(data, offset, key)

        if var_type == 0xBE00:  # \r
            return "\\r", offset, key
        elif var_type == 0xBE01:  # \c
            return "\\c", offset, key
        elif var_type == 0xBE02:  # [WAIT]
            arg, offset, key = self.decrypt_u16(data, offset, key)
            return f"[WAIT {arg}]", offset, key
        elif var_type == 0xBDFF:  # [~]
            arg, offset, key = self.decrypt_u16(data, offset, key)
            return f"[~ {arg}]", offset, key
        else:
            # Handle other variable types
            var_name = self.get_variable_name(var_type)
            result = f"[VAR {var_name}"

            if length > 1:
                result += "("
                for i in range(length - 1):
                    arg, offset, key = self.decrypt_u16(data, offset, key)
                    result += f"{arg:04X}"
                    if i < length - 2:
                        result += ","
                result += ")"
            result += "]"
            return result, offset, key

    def get_variable_name(self, var_code):
        # Map variable codes to names
        var_names = {
            0xFF00: "COLOR", 0x0100: "TRNAME", 0x0101: "PKNAME", 0x0102: "PKNICK",
            0x0103: "TYPE", 0x0105: "LOCATION", 0x0106: "ABILITY", 0x0107: "MOVE",
            0x0108: "ITEM1", 0x0109: "ITEM2", 0x010A: "sTRBAG", 0x010B: "BOX",
            0x010D: "EVSTAT", 0x0110: "OPOWER", 0x0127: "RIBBON", 0x0134: "MIINAME",
            0x013E: "WEATHER", 0x0189: "TRNICK", 0x018A: "1stchrTR", 0x018B: "SHOUTOUT",
            0x018E: "BERRY", 0x018F: "REMFEEL", 0x0190: "REMQUAL", 0x0191: "WEBSITE",
            0x019C: "CHOICECOS", 0x01A1: "GSYNCID", 0x0192: "PRVIDSAY", 0x0193: "BTLTEST",
            0x0195: "GENLOC", 0x0199: "CHOICEFOOD", 0x019A: "HOTELITEM", 0x019B: "TAXISTOP",
            0x019F: "MAISTITLE", 0x1000: "ITEMPLUR0", 0x1001: "ITEMPLUR1", 0x1100: "GENDBR",
            0x1101: "NUMBRNCH", 0x1302: "iCOLOR2", 0x1303: "iCOLOR3", 0x0200: "NUM1",
            0x0201: "NUM2", 0x0202: "NUM3", 0x0203: "NUM4", 0x0204: "NUM5", 0x0205: "NUM6",
            0x0206: "NUM7", 0x0207: "NUM8", 0x0208: "NUM9"
        }
        return var_names.get(var_code, f"{var_code:04X}")

    def get_strings_from_dat(self, file_path):
        # Parse the .dat file structure and decrypt text entries
        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < 16:
            return []

        text_sections = struct.unpack_from('<H', data, 0)[0]
        line_count = struct.unpack_from('<H', data, 2)[0]
        total_length = struct.unpack_from('<I', data, 4)[0]
        initial_key = struct.unpack_from('<I', data, 8)[0]
        section_data = struct.unpack_from('<i', data, 12)[0]

        if line_count == 0:
            return []

        if initial_key != 0:
            raise Exception("Invalid initial key!")

        if section_data + total_length != len(data) or text_sections != 1:
            raise Exception("Invalid Text File")

        section_length = struct.unpack_from('<I', data, section_data)[0]
        if section_length != total_length:
            raise Exception("Section size and overall size do not match.")

        lines = []
        key = 0x7C89

        for i in range(line_count):
            offset = struct.unpack_from('<I', data, section_data + 4 + i * 8)[0] + section_data
            length = struct.unpack_from('<H', data, section_data + 8 + i * 8)[0]

            line_key = key
            result = ''
            chars_decoded = 0

            while chars_decoded < length:
                val, offset, line_key = self.decrypt_u16(data, offset, line_key)
                chars_decoded += 1

                if val == 0:
                    break
                elif val == 0x0A:  # Newline
                    result += "\\n"
                elif val == 0x10:  # Variable
                    var_str, offset, line_key = self.decrypt_variable(data, offset, line_key)
                    result += var_str
                    # variables consume additional characters beyond the 0x10
                    chars_decoded = length  # break the loop as variable handler advanced offset
                else:
                    # Handle special characters mapping
                    if val == 0xE07F:
                        result += '\u202F'  # narrow no-break space
                    elif val == 0xE08D:
                        result += '…'  # ellipsis
                    elif val == 0xE08E:
                        result += '♂'  # male symbol
                    elif val == 0xE08F:
                        result += '♀'  # female symbol
                    else:
                        result += chr(val)

            lines.append(result)
            key = (key + 0x2983) & 0xFFFF

        return lines

    def encrypt_u16(self, val, key):
        # Encrypt a 16-bit value with rolling key
        encrypted = val ^ key
        key = ((key << 3) | (key >> 13)) & 0xFFFF
        return struct.pack('<H', encrypted), key

    def get_variable_value(self, var_name):
        # Map variable names to codes (case-insensitive)
        var_codes = {
            "color": 0xFF00, "trname": 0x0100, "pkname": 0x0101, "pknick": 0x0102,
            "type": 0x0103, "location": 0x0105, "ability": 0x0106, "move": 0x0107,
            "item1": 0x0108, "item2": 0x0109, "strbag": 0x010A, "box": 0x010B,
            "evstat": 0x010D, "opower": 0x0110, "ribbon": 0x0127, "miiname": 0x0134,
            "weather": 0x013E, "trnick": 0x0189, "1stchrtr": 0x018A, "shoutout": 0x018B,
            "berry": 0x018E, "remfeel": 0x018F, "remqual": 0x0190, "website": 0x0191,
            "choicecos": 0x019C, "gsyncid": 0x01A1, "prvidsay": 0x0192, "bltest": 0x0193,
            "genloc": 0x0195, "choicefood": 0x0199, "hotelitem": 0x019A, "taxistop": 0x019B,
            "maistitle": 0x019F, "itemplur0": 0x1000, "itemplur1": 0x1001, "gendbr": 0x1100,
            "numbrnch": 0x1101, "icolor2": 0x1302, "icolor3": 0x1303, "num1": 0x0200,
            "num2": 0x0201, "num3": 0x0202, "num4": 0x0203, "num5": 0x0204, "num6": 0x0205,
            "num7": 0x0206, "num8": 0x0207, "num9": 0x0208
        }

        var_name_lower = var_name.lower()
        if var_name_lower in var_codes:
            return var_codes[var_name_lower]
        else:
            try:
                return int(var_name, 16)
            except ValueError:
                raise ValueError(f"Unknown variable name: {var_name}")

    def parse_variable(self, text, index):
        # Parse tokens from the editable text representation, returning token and new index
        i = index
        # Check for special sequences first
        if text[i:i+2] == '\\n':
            return '\\n', i+2, None
        elif text[i:i+2] == '\\r':
            return '\\r', i+2, None
        elif text[i:i+2] == '\\c':
            return '\\c', i+2, None

        # Check for variables in brackets

        if text[i] == '[':
            end_bracket = text.find(']', i)
            if end_bracket == -1:
                raise Exception("Unclosed bracket")

            content = text[i+1:end_bracket]
            parts = content.split(' ', 1)
            var_type = parts[0]

            if var_type == 'WAIT':
                arg = parts[1] if len(parts) > 1 else "0"
                return ('WAIT', arg), end_bracket+1, None
            elif var_type == '~':
                arg = parts[1] if len(parts) > 1 else "0"
                return ('~', arg), end_bracket+1, None
            elif var_type == 'VAR':
                var_content = parts[1] if len(parts) > 1 else ""
                paren_index = var_content.find('(')

                if paren_index == -1:
                    # No arguments
                    return ('VAR', var_content, []), end_bracket+1, None
                else:
                    # Has arguments
                    var_name = var_content[:paren_index]
                    args_str = var_content[paren_index+1:-1]  # Remove closing parenthesis
                    args = [int(arg, 16) for arg in args_str.split(',')] if args_str else []
                    return ('VAR', var_name, args), end_bracket+1, None

        # Regular character
        return text[i], i+1, None

    def get_bytes_for_file(self, lines):
        # Convert text lines back into the encrypted .dat binary format
        text_sections = 1
        line_count = len(lines)
        base_key = 0x7C89

        line_offsets = []
        line_lengths = []
        line_data = []

        # Build encrypted line data
        for i in range(line_count):
            line_key = base_key
            line_bytes = bytearray()

            j = 0
            while j < len(lines[i]):
                token, j, _ = self.parse_variable(lines[i], j)

                if token == '\\n':
                    encrypted, line_key = self.encrypt_u16(0x0A, line_key)
                    line_bytes.extend(encrypted)
                elif token == '\\r':
                    # \r variable
                    encrypted, line_key = self.encrypt_u16(0x10, line_key)
                    line_bytes.extend(encrypted)
                    encrypted, line_key = self.encrypt_u16(1, line_key)
                    line_bytes.extend(encrypted)
                    encrypted, line_key = self.encrypt_u16(0xBE00, line_key)
                    line_bytes.extend(encrypted)
                elif token == '\\c':
                    # \c variable
                    encrypted, line_key = self.encrypt_u16(0x10, line_key)
                    line_bytes.extend(encrypted)
                    encrypted, line_key = self.encrypt_u16(1, line_key)
                    line_bytes.extend(encrypted)
                    encrypted, line_key = self.encrypt_u16(0xBE01, line_key)
                    line_bytes.extend(encrypted)
                elif isinstance(token, tuple):
                    # Token is a variable tuple: ('WAIT', arg), ('~', arg), ('VAR', name, args)
                    if token[0] == 'WAIT':
                        encrypted, line_key = self.encrypt_u16(0x10, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(1, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(0xBE02, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(int(token[1]), line_key)
                        line_bytes.extend(encrypted)
                    elif token[0] == '~':
                        encrypted, line_key = self.encrypt_u16(0x10, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(1, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(0xBDFF, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(int(token[1]), line_key)
                        line_bytes.extend(encrypted)
                    elif token[0] == 'VAR':
                        var_code = self.get_variable_value(token[1])
                        args = token[2] if len(token) > 2 else []

                        encrypted, line_key = self.encrypt_u16(0x10, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(1 + len(args), line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(var_code, line_key)
                        line_bytes.extend(encrypted)

                        for arg in args:
                            encrypted, line_key = self.encrypt_u16(arg, line_key)
                            line_bytes.extend(encrypted)
                else:
                    # Regular character
                    char_code = ord(token)
                    if token == '\u202F':  #nbsp
                        char_code = 0xE07F
                    elif token == '…':
                        char_code = 0xE08D
                    elif token == '♂':
                        char_code = 0xE08E
                    elif token == '♀':
                        char_code = 0xE08F

                    encrypted, line_key = self.encrypt_u16(char_code, line_key)
                    line_bytes.extend(encrypted)

            # Add null terminator
            encrypted, line_key = self.encrypt_u16(0, line_key)
            line_bytes.extend(encrypted)

            # Pad to 4-byte alignment if needed
            if len(line_bytes) % 4 != 0:
                line_bytes.extend(b'\x00\x00')

            line_data.append(line_bytes)
            line_lengths.append(len(line_bytes) // 2)
            base_key = (base_key + 0x2983) & 0xFFFF

        # Calculate offsets
        current_offset = 4 + line_count * 8  # Start after section header and line entries
        for i in range(line_count):
            line_offsets.append(current_offset)
            current_offset += len(line_data[i])

        total_length = current_offset

        # Build binary result
        result = bytearray()

        # File header
        result.extend(struct.pack('<H', text_sections))  # textSections
        result.extend(struct.pack('<H', line_count))     # lineCount
        result.extend(struct.pack('<I', total_length))   # totalLength
        result.extend(struct.pack('<I', 0))              # initialKey
        result.extend(struct.pack('<I', 0x10))           # sectionData

        # Section header
        result.extend(struct.pack('<I', total_length))   # sectionLength

        # Line entries
        for i in range(line_count):
            result.extend(struct.pack('<I', line_offsets[i]))  # offset
            result.extend(struct.pack('<H', line_lengths[i]))  # length
            result.extend(struct.pack('<H', 0))                # padding

        # Line data
        for data in line_data:
            result.extend(data)

        return result

    # ---------- Scroll sync methods ----------
    def on_scrollbar(self, *args):
        # Called when vertical scrollbar is moved; sync both treeviews
        if self._syncing:
            return
        self._syncing = True
        try:
            # Apply the yview to the main tree
            self.tree.yview(*args)
            # Also apply to compare window if it exists
            if self.compare_window and self.compare_window.winfo_exists():
                try:
                    self.compare_window.tree.yview(*args)
                except Exception:
                    pass
        finally:
            self._syncing = False

    def on_main_mouse_wheel(self, event):
        # Handle mouse wheel (or touchpad) events on main tree and sync compare window
        try:
            if hasattr(event, 'delta') and event.delta:
                delta = -1 if event.delta > 0 else 1
            else:
                # event.num for Linux (4 up, 5 down)
                delta = -1 if getattr(event, 'num', None) == 4 else 1
        except Exception:
            delta = 1

        if self._syncing:
            return "break"
        self._syncing = True
        try:
            self.tree.yview_scroll(delta, "units")
            if self.compare_window and self.compare_window.winfo_exists():
                try:
                    self.compare_window.tree.yview_scroll(delta, "units")
                except Exception:
                    pass
        finally:
            self._syncing = False
        return "break"

    def on_compare_mouse_wheel(self, event):
        # Called by compare window's treewheel binding to ask main to sync
        try:
            if hasattr(event, 'delta') and event.delta:
                delta = -1 if event.delta > 0 else 1
            else:
                delta = -1 if getattr(event, 'num', None) == 4 else 1
        except Exception:
            delta = 1

        if self._syncing:
            return "break"
        self._syncing = True
        try:
            # Move both trees
            self.tree.yview_scroll(delta, "units")
            if self.compare_window and self.compare_window.winfo_exists():
                try:
                    self.compare_window.tree.yview_scroll(delta, "units")
                except Exception:
                    pass
        finally:
            self._syncing = False
        return "break"

    # ---------- Compare window management ----------
    def open_compare_window(self):
        # Open a compare window (Toplevel) and pass a reference to this editor
        if self.compare_window is None or not self.compare_window.winfo_exists():
            self.compare_window = CompareWindow(self)
        else:
            self.compare_window.lift()

    def highlight_differences(self):
        # If compare window is not available or not in compare mode, do nothing
        if not (self.compare_window and self.compare_window.winfo_exists()):
            return
        if not self.compare_window.compare_folder:
            return

        # Clear tags on both trees
        for item in self.tree.get_children():
            tags = tuple(t for t in self.tree.item(item, 'tags') if t not in ('diff_main', 'missing_in_compare', 'extra_in_compare'))
            self.tree.item(item, tags=tags)
        for item in self.compare_window.tree.get_children():
            tags = tuple(t for t in self.compare_window.tree.item(item, 'tags') if t not in ('diff_main', 'missing_in_compare', 'extra_in_compare'))
            self.compare_window.tree.item(item, tags=tags)

        main_lines = self.current_lines
        compare_lines = self.compare_window.current_lines

        # Create a more precise comparison by matching lines by index
        for i in range(len(main_lines)):
            main_item = self.tree.get_children()[i] if i < len(self.tree.get_children()) else None
            
            if i < len(compare_lines):
                compare_item = self.compare_window.tree.get_children()[i] if i < len(self.compare_window.tree.get_children()) else None
                
                if main_item and compare_item:
                    main_text = self.tree.item(main_item, 'values')[1]
                    compare_text = self.compare_window.tree.item(compare_item, 'values')[2]  # Column index 2 for text
                    
                    if main_text != compare_text:
                        self.tree.item(main_item, tags=('diff_main',))
                        self.compare_window.tree.item(compare_item, tags=('diff_main',))
            else:
                # Line exists in main but not in compare
                if main_item:
                    self.tree.item(main_item, tags=('missing_in_compare',))

        # Check for extra lines in compare
        for i in range(len(main_lines), len(compare_lines)):
            compare_item = self.compare_window.tree.get_children()[i] if i < len(self.compare_window.tree.get_children()) else None
            if compare_item:
                self.compare_window.tree.item(compare_item, tags=('extra_in_compare',))

        # ensure tag styles exist
        self.tree.tag_configure('diff_main', background='lightcoral')
        self.tree.tag_configure('missing_in_compare', background='lightcoral')
        self.tree.tag_configure('extra_in_compare', background='lightgreen')
        self.compare_window.tree.tag_configure('diff_main', background='lightcoral')
        self.compare_window.tree.tag_configure('missing_in_compare', background='lightcoral')
        self.compare_window.tree.tag_configure('extra_in_compare', background='lightgreen')

# ---------------- CompareWindow class (read-only viewer) ----------------
class CompareWindow(tk.Toplevel):
    def __init__(self, parent):
        # parent is instance of DATEditor
        super().__init__(parent.root)
        self.parent = parent
        self.title("Compare DAT Text Viewer")
        self.geometry("800x515")

        # folder and file state for compare window
        self.compare_folder = None
        self.files = []
        self.current_file_index = -1
        self.current_lines = []

        self.create_widgets()

    def create_widgets(self):
        # Top controls for compare window
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(top_frame, text="Open Compare Folder", command=self.open_folder).pack(side=tk.LEFT)
        self.path_label = ttk.Label(top_frame, text="No folder loaded")
        self.path_label.pack(side=tk.LEFT, padx=10)
        self.export_btn = ttk.Button(top_frame, text="Export TXT", command=self.export_txt, state=tk.DISABLED)  # Initially disabled
        self.export_btn.pack(side=tk.LEFT)

        # File selection combobox (optional)
        file_frame = ttk.Frame(self)
        file_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(file_frame, text="File:").pack(side=tk.LEFT)
        self.file_combo = ttk.Combobox(file_frame, state="readonly", width=60)
        self.file_combo.pack(side=tk.LEFT, padx=5)
        self.file_combo.bind('<<ComboboxSelected>>', self.on_file_select)
        # Add keyboard navigation
        self.file_combo.bind('<Down>', self.on_arrow_key)
        self.file_combo.bind('<Up>', self.on_arrow_key)

        # Treeview area
        editor_frame = ttk.Frame(self)
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        table_frame = ttk.Frame(editor_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)

        # Add extra column for copy buttons - Action first, then Line, then Text
        self.tree = ttk.Treeview(table_frame, columns=('action', 'index', 'text'), show='headings', selectmode='browse')
        self.tree.heading('action', text='')
        self.tree.column('action', width=40, minwidth=40, anchor='center', stretch=False)
        self.tree.heading('index', text='Line')
        self.tree.column('index', width=50, minwidth=50, anchor='center', stretch=False)
        self.tree.heading('text', text='Text')
        self.tree.column('text', minwidth=300, anchor='center', stretch=True)

        # Vertical scrollbar: delegate to parent's on_scrollbar for synchronization
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.on_scrollbar)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Bind mouse wheel on compare tree to notify parent to sync
        self.tree.bind('<MouseWheel>', lambda e: self.parent.on_compare_mouse_wheel(e))
        self.tree.bind('<Button-4>', lambda e: self.parent.on_compare_mouse_wheel(e))
        self.tree.bind('<Button-5>', lambda e: self.parent.on_compare_mouse_wheel(e))

        # configure tags for highlight
        self.tree.tag_configure('diff_main', background='lightcoral')
        self.tree.tag_configure('missing_in_compare', background='lightcoral')
        self.tree.tag_configure('extra_in_compare', background='lightgreen')

        # Bind click events
        self.tree.bind('<ButtonRelease-1>', self.on_tree_click)
        self.tree.bind('<Double-1>', self.on_double_click)

    def on_arrow_key(self, event):
        # Handle up/down arrow keys in file combobox
        current_index = self.file_combo.current()
        if event.keysym == 'Down' and current_index < len(self.files) - 1:
            self.file_combo.current(current_index + 1)
            self.load_file(current_index + 1)
        elif event.keysym == 'Up' and current_index > 0:
            self.file_combo.current(current_index - 1)
            self.load_file(current_index - 1)
        return "break"  # Prevent default behavior

    def on_tree_click(self, event):
        # Handle click on action column
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell":
            column = self.tree.identify_column(event.x)
            item = self.tree.identify_row(event.y)
            
            # If clicked on action column (column #1)
            if column == "#1" and item:
                self.copy_line_to_main(item)

    def on_double_click(self, event):
        # Handle double click to edit line
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell":
            column = self.tree.identify_column(event.x)
            item = self.tree.identify_row(event.y)
            
            # If clicked on text column (column #3)
            if column == "#3" and item:
                self.edit_line(item)

    def copy_line_to_main(self, item):
        # Copy this line to main editor
        values = self.tree.item(item, 'values')
        if len(values) < 3:
            return
            
        line_index = int(values[1])  # Index is in column 1
        text = values[2]  # Text is in column 2
        
        # Ensure main editor has enough lines
        while len(self.parent.current_lines) <= line_index:
            self.parent.current_lines.append("")
            
        # Update line in main editor
        self.parent.current_lines[line_index] = text
        self.parent.update_text_display()
        
        # Update highlight
        self.parent.highlight_differences()

    def edit_line(self, item):
        # Edit line in compare window
        values = self.tree.item(item, 'values')
        if len(values) < 3:
            return
            
        line_index = int(values[1])  # Index is in column 1
        current_text = values[2]  # Text is in column 2

        edit_dialog = tk.Toplevel(self)
        edit_dialog.title(f"Edit Line {line_index}")
        edit_dialog.geometry("500x300")
        edit_dialog.transient(self)
        edit_dialog.grab_set()

        edit_dialog.grid_rowconfigure(0, weight=1)
        edit_dialog.grid_columnconfigure(0, weight=1)

        text_area = ScrolledText(edit_dialog, wrap=tk.WORD)
        text_area.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        text_area.insert('1.0', current_text)

        button_frame = ttk.Frame(edit_dialog)
        button_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        def save_changes():
            new_text = text_area.get('1.0', tk.END).strip()
            self.current_lines[line_index] = new_text
            self.tree.item(item, values=('<<<', line_index, new_text))
            self.parent.highlight_differences()
            edit_dialog.destroy()
            
        # Copy / Paste helpers
        def copy_text():
            text_content = text_area.get("1.0", tk.END)
            root.clipboard_clear()
            root.clipboard_append(text_content)
            root.update()

        def paste_text():
            text_content = root.clipboard_get()
            text_area.delete("1.0", tk.END)
            text_area.event_generate("<<Paste>>")

        copy_btn = ttk.Button(button_frame, text="Copy", command=copy_text)
        copy_btn.pack(side=tk.LEFT, padx=5)
        paste_btn = ttk.Button(button_frame, text="Paste", command=paste_text)
        paste_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Cancel", command=edit_dialog.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Save", command=save_changes).pack(side=tk.RIGHT, padx=5)

    def on_scrollbar(self, *args):
        # Delegate scrollbar action to parent's handler to centralize sync logic
        self.parent.on_scrollbar(*args)

    def open_folder(self):
        folder_path = filedialog.askdirectory(title="Select Folder with .dat files")
        if not folder_path:
            return

        self.compare_folder = folder_path
        self.files = [os.path.join(folder_path, f) for f in os.listdir(folder_path)
                     if f.endswith('.dat') and os.path.isfile(os.path.join(folder_path, f))]

        if not self.files:
            messagebox.showerror("Error", "No .dat files found in selected folder")
            self.path_label.config(text="No folder loaded")
            self.file_combo['values'] = []
            self.current_file_index = -1
            self.current_lines = []
            self.update_text_display()
            self.export_btn.config(state=tk.DISABLED)  # Keep export disabled if no files
            return

        self.path_label.config(text=folder_path)
        self.file_combo['values'] = [os.path.basename(f) for f in self.files]
        self.file_combo.current(0)
        self.load_file(0)

    def load_file(self, index):
        # Load .dat file using parent's parser (reuse logic)
        self.current_file_index = index
        file_path = self.files[index]

        try:
            self.current_lines = self.parent.get_strings_from_dat(file_path)
            self.update_text_display()
            self.export_btn.config(state=tk.NORMAL)  # Enable export after successful load
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
            self.export_btn.config(state=tk.DISABLED)  # Keep export disabled on error

    def load_file_by_path(self, file_path):
        # Load by absolute path (used when main selects a file and we want same name)
        if not os.path.exists(file_path):
            raise FileNotFoundError(file_path)
        try:
            self.current_lines = self.parent.get_strings_from_dat(file_path)
            # if file_path not in self.files, add it and update combobox
            folder = os.path.dirname(file_path)
            if self.compare_folder != folder:
                # if different folder, set compare_folder to this folder and refresh list
                self.compare_folder = folder
                self.files = [os.path.join(folder, f) for f in os.listdir(folder)
                              if f.endswith('.dat') and os.path.isfile(os.path.join(folder, f))]
                self.file_combo['values'] = [os.path.basename(f) for f in self.files]
                # attempt to set current_file_index to this file
                bn = os.path.basename(file_path)
                if bn in self.file_combo['values']:
                    self.file_combo.current(self.file_combo['values'].index(bn))
            else:
                # ensure combo has the file selected if present
                bn = os.path.basename(file_path)
                if bn in self.file_combo['values']:
                    self.file_combo.current(self.file_combo['values'].index(bn))
            self.update_text_display()
            self.export_btn.config(state=tk.NORMAL)  # Enable export after successful load
        except Exception as e:
            self.export_btn.config(state=tk.DISABLED)  # Keep export disabled on error
            raise

    def on_file_select(self, event):
        self.load_file(self.file_combo.current())

    def update_text_display(self):
        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add new items with copy buttons
        for i, line in enumerate(self.current_lines):
            self.tree.insert('', 'end', values=('<<<', i, line))
            
    def export_txt(self):
        # Export current text to a .txt file (simple header + all lines)
        if not self.files or self.current_file_index < 0:
            return

        save_path = filedialog.asksaveasfilename(
            title="Export Text File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )

        if not save_path:
            return

        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                file_path = self.files[self.current_file_index]

                f.write("~~~~~~~~~~~~~~~\n")
                f.write(f"Text File: {os.path.basename(file_path)}\n")
                f.write("~~~~~~~~~~~~~~~\n")

                for line in self.current_lines:
                    f.write(line + '\n')

            messagebox.showinfo("Success", "Text exported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export text: {str(e)}")

# ----------------- Main program entry -----------------
if __name__ == "__main__":
    # Hide console window on Windows
    import platform
    if platform.system() == "Windows":
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    
    root = tk.Tk()
    app = DATEditor(root)
    root.mainloop()