
import csv
import os
from datetime import datetime

MACHINE_FILE = "machines.csv"
LOG_FILE = "inspection_log.csv"


# Create CSV files
def create_files():

    if not os.path.exists(MACHINE_FILE):
        with open(MACHINE_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Name", "Location"])

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Date", "Machine ID", "Temperature",
                "Vibration", "Hours", "Status", "Advice"
            ])


# Register a new machine
def register_machine():

    mid = input("Enter Machine ID: ")

    with open(MACHINE_FILE, "r") as f:
        reader = csv.DictReader(f)

        for row in reader:
            if row["ID"] == mid:
                print("Machine already registered!")
                return

    name = input("Enter Machine Name: ")
    location = input("Enter Location: ")

    with open(MACHINE_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([mid, name, location])

    print("Machine registered successfully!")


# Check whether machine exists
def machine_exists(mid):

    with open(MACHINE_FILE, "r") as f:
        reader = csv.DictReader(f)

        for row in reader:
            if row["ID"] == mid:
                return True

    return False


# Analyze machine condition
def analyze_machine(temp, vibration, hours):

    if temp >= 80 or vibration >= 7:
        return "CRITICAL", "Immediate inspection recommended"

    elif temp >= 65 or vibration >= 4 or hours >= 500:
        return "WARNING", "Maintenance check recommended"

    else:
        return "NORMAL", "Machine condition is normal"


# Inspect machine
def inspect_machine():

    mid = input("Enter Machine ID: ")

    if not machine_exists(mid):
        print("Machine not found! Register first.")
        return

    try:
        temp = float(input("Enter Temperature (C): "))
        vibration = float(input("Enter Vibration (mm/s): "))
        hours = float(input("Enter Operating Hours: "))

        if temp < 0 or vibration < 0 or hours < 0:
            print("Values cannot be negative!")
            return

    except ValueError:
        print("Please enter valid numbers!")
        return

    status, advice = analyze_machine(
        temp, vibration, hours
    )

    date = datetime.now().strftime("%d-%m-%Y %H:%M")

    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            date, mid, temp, vibration,
            hours, status, advice
        ])

    print("\n----- MACHINE HEALTH REPORT -----")
    print("Machine ID:", mid)
    print("Temperature:", temp, "C")
    print("Vibration:", vibration, "mm/s")
    print("Operating Hours:", hours)
    print("Status:", status)
    print("Advice:", advice)
    print("---------------------------------")


# View inspection history
def view_history():

    mid = input("Enter Machine ID: ")
    found = False

    with open(LOG_FILE, "r") as f:
        reader = csv.DictReader(f)

        print("\n----- INSPECTION HISTORY -----")

        for row in reader:
            if row["Machine ID"] == mid:
                print(row)
                found = True

    if not found:
        print("No inspection records found.")


# Main menu
def main():

    create_files()

    while True:

        print("\n===== MECHCARE SYSTEM =====")
        print("1. Register Machine")
        print("2. Inspect Machine")
        print("3. View Inspection History")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            register_machine()

        elif choice == "2":
            inspect_machine()

        elif choice == "3":
            view_history()

        elif choice == "4":
            print("Thank you for using MechCare!")
            break

        else:
            print("Invalid choice! Try again.")


main()
