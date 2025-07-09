import socket
import ssl
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
import time

HOST = "0.0.0.0"
PORT = 9999

clients = []
appliances = ["LIGHT", "AC", "FAN 1", "FAN 2", "GYSER", "HEATER"]
appliance_states = {a: False for a in appliances}
scheduled_actions = []  

#threading
triggered = set()
def schedule_monitor():
    while True:
        now = datetime.now().strftime("%H:%M")
        for action in scheduled_actions[:]:
            appl, state, trigger_time = action
            trigger = datetime.strptime(trigger_time, "%H:%M").time()
            trigger_time = trigger.strftime("%H:%M")
            if now >= trigger_time and action not in triggered:
                appliance_states[appl] = (state == "ON")
                broadcast_update(appl)
                draw_appliances()
                triggered.add(action)
                scheduled_actions.remove(action)
                log(f"[SCHEDULE TRIGGERED] {appl} set to {state}")
        time.sleep(1)
threading.Thread(target=schedule_monitor, daemon=True).start()

def handle_client(conn, addr):
    clients.append(conn)
    log(f"[NEW CLIENT] {addr}")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            msg = data.decode().strip()
            log(f"[{addr}] {msg}")
            process_command(msg, conn)
    except Exception as e:
        log(f"[ERROR] {addr}: {e}")
    finally:
        conn.close()
        if conn in clients:
            clients.remove(conn)
        log(f"[DISCONNECTED] {addr}")

def broadcast_update(appliance):
    if appliance in appliance_states:
        state = appliance_states[appliance]
        msg = f"{appliance} {'ON' if state else 'OFF'}"
    else:
        msg = appliance

    for c in clients[:]:
        try:
            c.sendall(msg.encode())
        except:
            clients.remove(c)

def toggle_state(appliance):
    appliance = appliance.upper()
    if appliance in appliance_states:
        appliance_states[appliance] = not appliance_states[appliance]
        draw_appliances()
        broadcast_update(appliance)

def process_command(msg, conn):
    parts = msg.split()
    if not parts:
        return

    cmd = parts[0].upper()
    users = {"tulika": "123", "admin": "admin","meghana": "123", "client": "client"}
    if cmd == "LOGIN"and len(parts) == 3:
        username = parts[1]
        password = parts[2]
        if users.get(username) == password:
            try:
                conn.sendall("LOGIN SUCCESS".encode())
                status_report = "\n".join([f"{k} {'ON' if v else 'OFF'}" for k, v in appliance_states.items()])
                conn.sendall(f"[STATUS]\n{status_report}".encode())
            except:
                pass
            log(f"[LOGIN SUCCESS] {username}")
            return
        else:
            conn.sendall("LOGIN FAILED".encode())
            log(f"[LOGIN FAILED] {username}")
        return

    elif cmd == "ADD" and len(parts) >= 2:
        name = " ".join(parts[1:]).upper()
        if name not in appliance_states:
            appliance_states[name] = False
            if name not in appliances:
                appliances.append(name)
            draw_appliances()
            broadcast_update(f"ADDED {name}")

    elif cmd == "REMOVE" and len(parts) >= 2:
        name = " ".join(parts[1:]).upper()
        if name in appliance_states:
            del appliance_states[name]
            if name in appliances:
                appliances.remove(name)
            draw_appliances()
            broadcast_update(f"{name} REMOVED")
            log(f"[REMOVED] {name}")

    elif cmd == "TIMER" and len(parts) >= 4:
        appl = parts[1].upper()
        state = parts[2].upper()
        secs = int(parts[3])
        log(f"[TIMER] {appl} will be {state} in {secs} seconds")
        broadcast_update(f"[TIMER SET] {appl} to be {state} on in {secs}s")

        def delayed_action():
            if appl in appliance_states:
                appliance_states[appl] = (state == "ON")
                draw_appliances()
                broadcast_update(appl)
            log(f"[TIMER TRIGGERED] {appl} set to {state}")


        threading.Timer(secs, delayed_action).start()

    elif cmd == "SCHEDULE" and len(parts) >= 4:
        appl = parts[1].upper()
        state = parts[2].upper()
        time_str = parts[3]
        scheduled_actions.append((appl, state, time_str))
        log(f"[SCHEDULED] {appl} will be {state} at {time_str}")
        broadcast_update(f"[SCHEDULE SET] {appl} to be {state} at {time_str}")

    elif cmd == "STATUS":
        status_report = "\n".join([f"{k}: {'ON' if v else 'OFF'}" for k, v in appliance_states.items()])
        try:
            conn.sendall(f"[STATUS]\n{status_report}".encode())
        except:
            pass

    elif len(parts) >= 2:
        appl = " ".join(parts[:-1]).upper()
        state = parts[-1].upper()
        if appl in appliance_states:
            appliance_states[appl] = (state == "ON")
            draw_appliances()
            broadcast_update(appl)

def start_server():
    threading.Thread(target=run_server, daemon=True).start()
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    log("[SERVER STARTED]")

def stop_server():
    for c in clients:
        try:
            c.sendall("SERVER STOPPED".encode())
        except:
            pass
        c.close()
    clients.clear()
    log("[SERVER STOPPED]")
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def run_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    context.load_verify_locations("ca.crt") 
    context.verify_mode = ssl.CERT_REQUIRED

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    log(f"[LISTENING] on {HOST}:{PORT}")
    
    while True:
        conn, addr = server.accept()
        try:
            ssl_conn = context.wrap_socket(conn, server_side=True)
            cert = ssl_conn.getpeercert()
            log(f"[NEW SSL CONNECTION] {addr} | CERT: {cert['subject'][0][0][1]}")
            threading.Thread(target=handle_client, args=(ssl_conn, addr), daemon=True).start()
        except ssl.SSLError as e:
            log(f"[SSL ERROR] {addr}: {e}")
            conn.close()

root = tk.Tk()
root.title("Home Automation Switch Server")
root.configure(bg="black")
root.geometry("360x640")

title = tk.Label(root, text="Home Automation Server", font=("Arial", 14, "bold"), fg="white", bg="black")
title.pack(pady=10)

log_box = scrolledtext.ScrolledText(root, height=10, width=58, bg="white", fg="black", font=("Arial", 10))
log_box.pack(pady=5)

appliance_frame = tk.Frame(root, bg="black")
appliance_frame.pack(pady=10)

def draw_appliances():
    for widget in appliance_frame.winfo_children():
        widget.destroy()
    for i, appliance in enumerate(appliances):
        display_name = appliance.title().upper()
        state = appliance_states.get(appliance, False)
        tk.Label(appliance_frame, text=display_name, bg="black", fg="white", font=("Arial", 10))\
            .grid(row=i, column=0, padx=10, pady=4, sticky="w")

        btn_color = "green" if state else "red"
        btn = tk.Button(appliance_frame, text="ON" if state else "OFF",
                        bg=btn_color, fg="white", width=6,
                        command=lambda a=appliance: toggle_state(a))
        btn.grid(row=i, column=1, padx=10, pady=4)

def log(message):
    print(message)
    log_box.insert(tk.END, f"{message}\n")
    log_box.see(tk.END)

btn_frame = tk.Frame(root, bg="black")
btn_frame.pack(pady=15)

start_btn = tk.Button(btn_frame, text="Start Server", command=start_server,
                      bg="#4FC3F7", width=15, height=2, font=("Arial", 10, "bold"))
start_btn.grid(row=0, column=0, padx=10)

stop_btn = tk.Button(btn_frame, text="Stop Server", command=stop_server,
                     bg="#E57373", width=15, height=2, font=("Arial", 10, "bold"), state="disabled")
stop_btn.grid(row=0, column=1, padx=10)

draw_appliances()
root.mainloop()
