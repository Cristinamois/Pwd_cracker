import hashlib
import itertools
import string
import tkinter as tk
from tkinter import ttk, messagebox
import threading

stop_flag = False

def hash_word(word, algorithm='md5'):
    word = word.encode()
    if algorithm == 'md5':
        return hashlib.md5(word).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(word).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(word).hexdigest()
    else:
        raise ValueError(f"Algorithme non supporté : {algorithm}")

def crack_with_dict(target_hash, algorithm='md5', wordlist_path="wordlist.txt", update_callback=None):
    try:
        with open(wordlist_path, "r") as f:
            for line in f:
                if stop_flag:
                    return None
                word = line.strip()
                if update_callback:
                    update_callback(word)
                if hash_word(word, algorithm) == target_hash:
                    return word
    except FileNotFoundError:
        return f"[!] Fichier introuvable : {wordlist_path}"
    return None

def crack_with_bruteforce(target_hash, algorithm='md5', max_length=4, use_specials=False, progress_callback=None, update_callback=None):
    global stop_flag

    chars = string.ascii_lowercase + string.digits
    if use_specials:
        chars += "!@#$%^&*()-_=+[]{}|;:',.<>?/\\\""

    total = sum(len(chars)**length for length in range(1, max_length + 1))
    count = 0

    for length in range(1, max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            if stop_flag:
                return None
            word = ''.join(attempt)
            if update_callback:
                update_callback(word)
            if hash_word(word, algorithm) == target_hash:
                return word
            count += 1
            if progress_callback:
                progress_callback(count / total * 100)
    return None

def start_cracking_thread():
    global stop_flag
    stop_flag = False
    result_label.config(text="", foreground="green")
    progress_bar['value'] = 0
    tried_words_text.config(state='normal')
    tried_words_text.delete("1.0", tk.END)
    tried_words_text.config(state='disabled')
    threading.Thread(target=launch_cracking, daemon=True).start()

def launch_cracking():
    target_hash = hash_entry.get().strip()
    algorithm = algo_choice.get()
    method = method_choice.get()

    if not target_hash:
        messagebox.showwarning("Erreur", "Veuillez entrer un hash.")
        return

    def update_progress(percent):
        progress_bar['value'] = percent

    def update_tried_words(word):
        # Ajoute le mot essayé dans le widget text, et scroll automatique
        tried_words_text.config(state='normal')
        tried_words_text.insert(tk.END, word + "\n")
        tried_words_text.see(tk.END)
        tried_words_text.config(state='disabled')

    if method == "dico":
        result = crack_with_dict(target_hash, algorithm, update_callback=update_tried_words)
        progress_bar['value'] = 100
    else:
        try:
            max_len = int(length_entry.get())
        except ValueError:
            max_len = 4
        use_specials = special_var.get()
        result = crack_with_bruteforce(target_hash, algorithm, max_len, use_specials, update_progress, update_tried_words)

    if stop_flag:
        result_label.config(text="[!] Attaque stoppée par l'utilisateur.", foreground="orange")
        progress_bar['value'] = 0
    elif result:
        result_label.config(text=f"[✔] Mot de passe trouvé : {result}", foreground="green")
        progress_bar['value'] = 100
    else:
        result_label.config(text="[✘] Mot de passe introuvable.", foreground="red")
        progress_bar['value'] = 100

def stop_cracking():
    global stop_flag
    stop_flag = True

# --- UI ---

root = tk.Tk()
root.title("Password Cracker")
root.geometry("500x600")
root.resizable(False, False)

# Styles
style = ttk.Style()
style.theme_use('clam')
style.configure("TButton", font=("Helvetica", 12), padding=6)
style.configure("TLabel", font=("Helvetica", 12))
style.configure("TCombobox", font=("Helvetica", 12))
style.configure("TCheckbutton", font=("Helvetica", 12))

padding_opts = {'padx': 10, 'pady': 5}

frame = ttk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True, **padding_opts)

ttk.Label(frame, text="Hash à cracker :").grid(row=0, column=0, sticky='w')
hash_entry = ttk.Entry(frame, width=45)
hash_entry.grid(row=0, column=1, sticky='ew')

ttk.Label(frame, text="Algorithme :").grid(row=1, column=0, sticky='w')
algo_choice = ttk.Combobox(frame, values=["md5", "sha1", "sha256"], state="readonly", width=43)
algo_choice.set("md5")
algo_choice.grid(row=1, column=1, sticky='ew')

ttk.Label(frame, text="Méthode :").grid(row=2, column=0, sticky='w')
method_choice = ttk.Combobox(frame, values=["dico", "brute"], state="readonly", width=43)
method_choice.set("dico")
method_choice.grid(row=2, column=1, sticky='ew')

ttk.Label(frame, text="Longueur max (brute force) :").grid(row=3, column=0, sticky='w')
length_entry = ttk.Entry(frame, width=10)
length_entry.insert(0, "4")
length_entry.grid(row=3, column=1, sticky='w')

special_var = tk.BooleanVar()
special_cb = ttk.Checkbutton(frame, text="Inclure caractères spéciaux", variable=special_var)
special_cb.grid(row=4, column=1, sticky='w')

btn_start = ttk.Button(frame, text="Lancer l'attaque", command=start_cracking_thread)
btn_start.grid(row=5, column=0, sticky='ew', pady=10, columnspan=2)

btn_stop = ttk.Button(frame, text="Stop", command=stop_cracking)
btn_stop.grid(row=6, column=0, sticky='ew', pady=(0, 10), columnspan=2)

progress_bar = ttk.Progressbar(frame, length=450, mode='determinate')
progress_bar.grid(row=7, column=0, columnspan=2, pady=10)

ttk.Label(frame, text="Combinaisons testées :").grid(row=8, column=0, sticky='w', pady=(10,0), columnspan=2)

tried_words_text = tk.Text(frame, height=15, width=58, state='disabled', bg='#f0f0f0', font=("Consolas", 10))
tried_words_text.grid(row=9, column=0, columnspan=2, sticky='nsew')

result_label = ttk.Label(frame, text="", foreground="green", font=("Helvetica", 14))
result_label.grid(row=10, column=0, columnspan=2, pady=15)

# Config grid weights pour que le text prenne de la place si resize (optionnel)
frame.columnconfigure(1, weight=1)
frame.rowconfigure(9, weight=1)

root.mainloop()
