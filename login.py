
import tkinter as tk
from tkinter import messagebox
from auth import verify_login

BG = "#0B1220"
CARD = "#142238"
BLUE = "#2563EB"
LIGHT_BLUE = "#60A5FA"
WHITE = "#F8FAFC"
MUTED = "#94A3B8"


class MechCareLogin:

    def __init__(self, root, on_success):
        self.root = root
        self.on_success = on_success

        root.title("MechCare | Secure Login")
        root.geometry("520x560")
        root.configure(bg=BG)
        root.resizable(False, False)

        container = tk.Frame(
            root,
            bg=CARD,
            padx=40,
            pady=35
        )
        container.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        tk.Label(
            container,
            text="⚙",
            font=("Arial", 38),
            fg=LIGHT_BLUE,
            bg=CARD
        ).pack()

        tk.Label(
            container,
            text="MechCare",
            font=("Arial", 27, "bold"),
            fg=WHITE,
            bg=CARD
        ).pack()

        tk.Label(
            container,
            text="SMART MACHINE MAINTENANCE",
            font=("Arial", 9),
            fg=MUTED,
            bg=CARD
        ).pack(pady=(0, 30))

        tk.Label(
            container,
            text="Username",
            fg=WHITE,
            bg=CARD,
            font=("Arial", 11)
        ).pack(anchor="w")

        self.username = tk.Entry(
            container,
            font=("Arial", 12),
            bg="#1E304A",
            fg=WHITE,
            insertbackground=WHITE,
            relief="flat",
            width=32
        )
        self.username.pack(ipady=10, pady=(7, 20))

        tk.Label(
            container,
            text="Password",
            fg=WHITE,
            bg=CARD,
            font=("Arial", 11)
        ).pack(anchor="w")

        self.password = tk.Entry(
            container,
            font=("Arial", 12),
            bg="#1E304A",
            fg=WHITE,
            insertbackground=WHITE,
            show="*",
            relief="flat",
            width=32
        )
        self.password.pack(ipady=10, pady=7)

        self.show_password = tk.BooleanVar()

        tk.Checkbutton(
            container,
            text="Show Password",
            variable=self.show_password,
            command=self.toggle_password,
            bg=CARD,
            fg=MUTED,
            activebackground=CARD,
            activeforeground=WHITE,
            selectcolor=CARD
        ).pack(anchor="w", pady=5)

        tk.Button(
            container,
            text="SIGN IN",
            command=self.login,
            bg=BLUE,
            fg=WHITE,
            activebackground=LIGHT_BLUE,
            activeforeground=WHITE,
            font=("Arial", 12, "bold"),
            relief="flat",
            cursor="hand2"
        ).pack(fill="x", ipady=11, pady=(20, 10))

        tk.Label(
            container,
            text="Secure Access | MechCare System",
            fg=MUTED,
            bg=CARD,
            font=("Arial", 9)
        ).pack(pady=8)

        self.password.bind("<Return>", lambda event: self.login())
        self.username.focus_set()

    def toggle_password(self):
        self.password.config(
            show="" if self.show_password.get() else "*"
        )

    def login(self):
        username = self.username.get().strip()
        password = self.password.get()

        if not username or not password:
            messagebox.showwarning(
                "Login",
                "Enter username and password."
            )
            return

        user = verify_login(username, password)

        if user:
            messagebox.showinfo(
                "Welcome",
                f"Welcome {user['username']}!\nRole: {user['role']}"
            )

            self.on_success(user)

        else:
            messagebox.showerror(
                "Login Failed",
                "Invalid username or password."
            )
