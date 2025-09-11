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
        
        self.files = []
        self.current_file_index = -1
        self.current_lines = []
        
        self.create_widgets()
        
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
        
        self.path_label = ttk.Label(top_frame, text="No folder loaded")
        self.path_label.pack(side=tk.LEFT, padx=10)
        
        # File selection
        file_frame = ttk.Frame(self.root)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(file_frame, text="File:").pack(side=tk.LEFT)
        self.file_combo = ttk.Combobox(file_frame, state="readonly", width=50)
        self.file_combo.pack(side=tk.LEFT, padx=5)
        self.file_combo.bind('<<ComboboxSelected>>', self.on_file_select)
        
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
        self.tree.column('index', width=50, minwidth=50)
        self.tree.heading('text', text='Text')
        self.tree.column('text', minwidth=400)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout for proper scrolling
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
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
        
    def open_folder(self):
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
        self.file_combo.current(0)
        self.load_file(0)
        
        # Enable buttons
        self.save_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL)
        self.import_btn.config(state=tk.NORMAL)
        
    def load_file(self, index):
        self.current_file_index = index
        file_path = self.files[index]
        
        try:
            self.current_lines = self.get_strings_from_dat(file_path)
            self.update_text_display()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
            
    def on_file_select(self, event):
        self.load_file(self.file_combo.current())
        
    def update_text_display(self):
        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Add new items
        for i, line in enumerate(self.current_lines):
            self.tree.insert('', 'end', values=(i, line))
            
    def on_double_click(self, event):
        item = self.tree.selection()[0] if self.tree.selection() else None
        if item:
            self.edit_line(item)
            
    def on_tree_select(self, event):
        # Update current_lines with any changes from the treeview
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if len(values) >= 2:
                line_index = int(values[0])
                new_text = values[1]
                if line_index < len(self.current_lines) and self.current_lines[line_index] != new_text:
                    self.current_lines[line_index] = new_text
            
    def edit_line(self, item):
        # Получаем текущие значения
        values = self.tree.item(item, 'values')
        line_index = int(values[0])
        current_text = values[1]
        
        # Создаём окно редактирования
        edit_dialog = tk.Toplevel(self.root)
        edit_dialog.title(f"Edit Line {line_index}")
        edit_dialog.geometry("500x300")
        edit_dialog.transient(self.root)
        edit_dialog.grab_set()
        
        # Настраиваем grid для корректного расширения
        edit_dialog.grid_rowconfigure(0, weight=1)
        edit_dialog.grid_columnconfigure(0, weight=1)
        
        # Текстовая область
        text_area = ScrolledText(edit_dialog, wrap=tk.WORD)
        text_area.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        text_area.insert('1.0', current_text)
        
        # Фрейм для кнопок
        button_frame = ttk.Frame(edit_dialog)
        button_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        def save_changes():
            new_text = text_area.get('1.0', tk.END).strip()
            self.current_lines[line_index] = new_text
            self.tree.item(item, values=(line_index, new_text))
            edit_dialog.destroy()
        
        # Кнопки Save и Cancel
        cancel_btn = ttk.Button(button_frame, text="Cancel", command=edit_dialog.destroy)
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        save_btn = ttk.Button(button_frame, text="Save", command=save_changes)
        save_btn.pack(side=tk.RIGHT, padx=5)
        
    def add_line(self):
        # Add new line at the end
        self.current_lines.append("New line")
        self.update_text_display()
        
    def remove_line(self):
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

    # DAT file handling methods (unchanged from previous implementation)
    def decrypt_u16(self, data, offset, key):
        val = struct.unpack_from('<H', data, offset)[0] ^ key
        offset += 2
        key = ((key << 3) | (key >> 13)) & 0xFFFF
        return val, offset, key

    def decrypt_variable(self, data, offset, key):
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
            start_offset = offset
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
                    # Variables consume additional characters beyond the 0x10
                    chars_decoded = length  # Exit the loop as variable handling advances offset
                else:
                    # Handle special characters
                    if val == 0xE07F:
                        result += '\u202F'  # nbsp
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
        
        # Convert to lowercase for case-insensitive lookup
        var_name_lower = var_name.lower()
        
        if var_name_lower in var_codes:
            return var_codes[var_name_lower]
        else:
            # Try to parse as hexadecimal number
            try:
                return int(var_name, 16)
            except ValueError:
                raise ValueError(f"Unknown variable name: {var_name}")

    def parse_variable(self, text, index):
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
        # Calculate total size needed
        text_sections = 1
        line_count = len(lines)
        base_key = 0x7C89
        
        # First pass: calculate the size of the data section
        data_size = 4  # Section length field
        
        line_offsets = []
        line_lengths = []
        line_data = []
        
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
                    if token[0] == 'WAIT':
                        # WAIT variable
                        encrypted, line_key = self.encrypt_u16(0x10, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(1, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(0xBE02, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(int(token[1]), line_key)
                        line_bytes.extend(encrypted)
                    elif token[0] == '~':
                        # ~ variable
                        encrypted, line_key = self.encrypt_u16(0x10, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(1, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(0xBDFF, line_key)
                        line_bytes.extend(encrypted)
                        encrypted, line_key = self.encrypt_u16(int(token[1]), line_key)
                        line_bytes.extend(encrypted)
                    elif token[0] == 'VAR':
                        # VAR variable
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
                    # Handle special characters
                    if token == '\u202F':  # nbsp
                        char_code = 0xE07F
                    elif token == '…':  # ellipsis
                        char_code = 0xE08D
                    elif token == '♂':  # male symbol
                        char_code = 0xE08E
                    elif token == '♀':  # female symbol
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
            line_lengths.append(len(line_bytes) // 2)  # Length in characters
            base_key = (base_key + 0x2983) & 0xFFFF
        
        # Calculate offsets
        current_offset = 4 + line_count * 8  # Start after section header and line entries
        for i in range(line_count):
            line_offsets.append(current_offset)
            current_offset += len(line_data[i])
            
        # Calculate total data size
        total_length = current_offset
        
        # Now build the file
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

if __name__ == "__main__":
    root = tk.Tk()
    app = DATEditor(root)
    root.mainloop()