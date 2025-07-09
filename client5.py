import ssl
import socket
import threading
import tkinter as tk

server_ip = "192.168.1.37"
server_port = 9999

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="ca.crt")
context.load_cert_chain(certfile="client.crt", keyfile="client.key")
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED
client_socket = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=server_ip)
client_socket.connect((server_ip, server_port))

print("[CLIENT] Connected with cert:", client_socket.getpeercert())

appliances = ["LIGHT", "AC", "FAN 1", "FAN 2", "GYSER", "HEATER"]
appliance_states = {a: False for a in appliances}

#threading
def receive_messages():
    while True:
        try:
            data = client_socket.recv(1024).decode()
            if not data:
                break
            
            if data.startswith("[STATUS]"):
                log_box.insert(tk.END, f"{data}\n")
                lines = data.splitlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        appliance = " ".join(parts[:-1])
                        state = parts[-1]
                        if appliance in appliance_states:
                            appliance_states[appliance] = (state.upper() == "ON")
                        log_box.see(tk.END)

            elif data.endswith("REMOVED"):
                name = data.replace(" REMOVED", "")
                if name in appliances:
                    appliances.remove(name)
                    appliance_states.pop(name, None)
                    draw_appliance_buttons()
            
            elif data.startswith("ADDED"):
                name = data.replace("ADDED", "").strip()
                if name not in appliances:
                    appliances.append(name)
                    appliance_states[name] = False
                    draw_appliance_buttons()
            
            elif any(data.startswith(appl) for appl in appliances):
                parts = data.split()
                if len(parts) >= 2:
                    appl = " ".join(parts[:-1])
                    state = parts[-1]
                if appl not in appliances:
                    appliances.append(appl)
                appliance_states[appl] = (state.upper() == "ON")
                draw_appliance_buttons()
            
            else:
                log_box.insert(tk.END, f"{data}\n")
            log_box.see(tk.END)
        
        except Exception as e:
            log_box.insert(tk.END, f"[ERROR] {e}\n")
            log_box.see(tk.END)
            break
            

threading.Thread(target=receive_messages, daemon=True).start()

def dark_input_dialog(title, prompt, is_password=False):
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.configure(bg="black")
    dialog.geometry("300x130")
    dialog.resizable(False, False)

    tk.Label(dialog, text=prompt, bg="black", fg="white", font=("Arial", 11)).pack(pady=10)
    entry_var = tk.StringVar()
    entry = tk.Entry(dialog, textvariable=entry_var, show="*" if is_password else "", font=("Arial", 11), bg="#333", fg="white")
    entry.pack(pady=5)
    entry.focus()

    def on_submit():
        dialog.user_input = entry_var.get()
        dialog.destroy()

    tk.Button(dialog, text="OK", command=on_submit, bg="#4FC3F7", font=("Arial", 10, "bold")).pack(pady=5)
    dialog.user_input = None
    dialog.grab_set()
    root.wait_window(dialog)
    return dialog.user_input

def send_cmd(cmd):
    try:
        client_socket.send(cmd.encode())
        log_box.insert(tk.END, f"> {cmd}\n")
        log_box.see(tk.END)
    except:
        log_box.insert(tk.END, "[ERROR] Cannot send command\n")

def toggle_appliance(appliance):
    appliance_states[appliance] = not appliance_states[appliance]
    state = "ON" if appliance_states[appliance] else "OFF"
    send_cmd(f"{appliance.upper()} {state}")
    draw_appliance_buttons()

def draw_appliance_buttons():
    for widget in appliance_frame.winfo_children():
        widget.destroy()
    for i, appliance in enumerate(appliances):
        label = tk.Label(appliance_frame, text=appliance, bg="black", fg="white", font=("Arial", 10))
        label.grid(row=i//2, column=(i%2)*2, padx=10, pady=5, sticky="w")

        btn_color = "green" if appliance_states.get(appliance, False) else "red"
        btn = tk.Canvas(appliance_frame, width=30, height=20, bg="black", highlightthickness=0)
        btn.create_oval(2, 2, 18, 18, fill=btn_color)
        btn.grid(row=i//2, column=(i%2)*2 + 1, padx=5)
        btn.bind("<Button-1>", lambda e, a=appliance: toggle_appliance(a))

def on_add():
    new_appl = dark_input_dialog("Add Appliance", "Appliance name:")
    if new_appl:
        appliances.append(new_appl.upper())
        appliance_states[new_appl.upper()] = False
        send_cmd(f"ADD {new_appl.upper()}")
        draw_appliance_buttons()

def on_remove():
    rem_appl = dark_input_dialog("Remove Appliance", "Appliance name:")
    if rem_appl and rem_appl.upper() in appliances:
        send_cmd(f"REMOVE {rem_appl.upper()}")

def on_timer():
    appl = dark_input_dialog("Timer", "Appliance?")
    state = dark_input_dialog("Timer", "ON or OFF?")
    secs = dark_input_dialog("Timer", "Seconds?")
    if appl and state and secs:
        send_cmd(f"TIMER {appl.upper()} {state.upper()} {secs}")

def on_schedule():
    appl = dark_input_dialog("Schedule", "Appliance?")
    state = dark_input_dialog("Schedule", "ON or OFF?")
    t = dark_input_dialog("Schedule", "Time (HH:MM)?")
    if appl and state and t:
        send_cmd(f"SCHEDULE {appl.upper()} {state.upper()} {t}")

def on_status():
    send_cmd("STATUS")

root = tk.Tk()
root.title("Home Automation Switch")
root.configure(bg="black")
root.geometry("360x640")

title = tk.Label(root, text="Home Automation Switch", font=("Arial", 14, "bold"), fg="white", bg="black")
title.pack(pady=(10, 5))

log_box = tk.Text(root, height=5, width=44, bg="white", fg="black", font=("Arial", 10))
log_box.pack(pady=(5, 10))

appliance_frame = tk.Frame(root, bg="black")
appliance_frame.pack()

btn_frame = tk.Frame(root, bg="black")
btn_frame.pack(pady=15)

def styled_button(txt, cmd, color):
    return tk.Button(btn_frame, text=txt, bg=color, fg="black", font=("Arial", 11, "bold"),
                     width=12, height=2, command=cmd)

styled_button("Set Timer", on_timer, "#4FC3F7").grid(row=0, column=0, padx=5, pady=5)
styled_button("ADD NEW", on_add, "#CE93D8").grid(row=0, column=1, padx=5, pady=5)
styled_button("Get Status", on_status, "#4FC3F7").grid(row=1, column=0, padx=5, pady=5)
styled_button("REMOVE", on_remove, "#80DEEA").grid(row=1, column=1, padx=5, pady=5)
styled_button("Schedule", on_schedule, "#4FC3F7").grid(row=2, column=0, padx=5, pady=5)
styled_button("Exit", root.quit, "#EF9A9A").grid(row=2, column=1, padx=5, pady=5)

login_win = tk.Toplevel(root)
login_win.title("Login")
login_win.geometry("300x200")
login_win.configure(bg="black")

login_user = tk.StringVar()
login_pass = tk.StringVar()

tk.Label(login_win, text="Username:", bg="black", fg="white", font=("Arial", 11)).pack(pady=5)
tk.Entry(login_win, textvariable=login_user, bg="#333", fg="white").pack(pady=5)

tk.Label(login_win, text="Password:", bg="black", fg="white", font=("Arial", 11)).pack(pady=5)
tk.Entry(login_win, textvariable=login_pass, show="*", bg="#333", fg="white").pack(pady=5)

def login():
    username = login_user.get()
    password = login_pass.get()
    if username and password:
        send_cmd(f"LOGIN {username} {password}")
        login_win.destroy()

tk.Button(login_win, text="Login", command=login, bg="#4FC3F7", font=("Arial", 11, "bold")).pack(pady=10)
login_win.grab_set()


draw_appliance_buttons()
root.mainloop()
