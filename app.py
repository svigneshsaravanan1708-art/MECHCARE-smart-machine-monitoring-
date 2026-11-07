
import tkinter as tk

from login import MechCareLogin
from auth import has_permission


def start_dashboard(user):

    root.destroy()

    import main

    # Connect this to your EXISTING dashboard startup.
    # Replace open_dashboard with your actual function.
    main.open_dashboard(user=user)


root = tk.Tk()

app = MechCareLogin(
    root,
    on_success=start_dashboard
)

root.mainloop()
