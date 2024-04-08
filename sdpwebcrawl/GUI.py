# GUI.py
import tkinter as tk
from tkinter import ttk
import sqlite3
import webbrowser
import tkinter.messagebox
from details import show_details

# stores current domain
selected_domain = None

def show_guide():
    guide_text = """

    Thank you for using SDP Hafiz Info Viewer!

    Walkthrough:
    1.  Scroll and click an SDP item under the "Hafiz Security Design Pattern (SDP)" 
        list to view details on an SDP.

    2.  Once an SDP has been found and clicked, a user is able to view information 
        related to that SDP based off the Hafiz website in the SDP details section 
        that is to the right of the "Hafiz Security Design Pattern (SDP)" list.

        i.  Click on the url link to the right of "URL:" to navigate to the Hafiz 
            source.

    3.  To find other resources that relate the SDP and relating information, a 
        user is presented a variety of buttons. beneath the SDP details section.
        Users can click on one of these buttons to be presented an ID and link. 
        A new list will appear on the right of the details section.

        i:  Each button has a corresponding confidence rank and are colored green 
            for HIGH, yellow for MEDIUM, and red for LOW. confidence ranks tell 
            users how reliable and trustworthy a resource is to SDP data.

        ii: if a user wants to alter a resource's confidence rank,they can left
            click a domain, then right-click on a button to change confidence level.

    4.  A user will be presented results of that resource related to the chosen
        SDP. Some results may appear empty, it is recommended that users look at
        a SDP's Related Patterns to find more information.

        i.  Each of these links are ranked 1-4 on how accurate the link is to
            the SDP (1 being most accurate). 1 uses the SDP name for parse, 2 uses 
            the SDP tags for parse. 3 uses the SDP class keys for parse, and 4 uses
            the SDP related patterns for parse.

        ii. Click on a list's cell to navigate to the source and read in detail.

    Notes:
    - Information was web scraped and obtained on 2/9/2024

    """

    tkinter.messagebox.showinfo("User Guide", guide_text)


# Get all data from hafiz table in db
def fetch_data_hafiz():
    query = "SELECT NAME, URL, CLASS_KEY, PROBLEM, SOLUTION, KNOWN_USES, RELATED_PATTERNS, TAGS FROM sdp_hafiz_info"
    cursor.execute(query)
    datatable = cursor.fetchall()
    return datatable


def open_webpage(url):
    webbrowser.open(url)


# Set values of hafiz items for initial tree
def sdp_click(event):
    selected_item = tree.selection()
    sources_frame.destroy()
    if selected_item:
        item_values = tree.item(selected_item, "values")
        name = item_values[0]
        url = item_values[1]
        class_key = item_values[2]
        problem = item_values[3]
        solution = item_values[4]
        known_uses = item_values[5]
        related_patterns = item_values[6]
        tags = item_values[7]
        show_details(name, url, class_key, problem, solution, known_uses, related_patterns, tags, root, cursor, conn)



# Main Page View
root = tk.Tk()
root.title("SDP Hafiz Info Viewer")
root.geometry("1600x800")

style = ttk.Style()
style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

tree = ttk.Treeview(root, columns="NAME", show="headings", height=35)
tree.heading("NAME", text="Hafiz Security Design Patterns (SDP)")

column_widths = {"NAME": 300}
for column, width in column_widths.items():
    tree.column(column, width=width)

tree.bind("<ButtonRelease-1>", sdp_click)

conn = sqlite3.connect("database_SDP.db")
cursor = conn.cursor()

# Confidence level memory
cursor.execute("""
    CREATE TABLE IF NOT EXISTS button_colors (
        button_name TEXT PRIMARY KEY,
        color TEXT
    )
""")

# Add data to the Treeview
data = fetch_data_hafiz()
for sdp in data:
    tree.insert("", "end", values=sdp)

tree.grid(row=0, column=0, padx=5, pady=10, sticky="nsew")

# Shows a user guide
button_guide = ttk.Button(root, text="User Guide", width=50, command=show_guide)
button_guide.grid(row=1, column=0, columnspan=1, pady=5)

# Create vertical scrollbar on the left side
vsb_main = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
vsb_main.grid(row=0, column=1, sticky="ns")
tree.configure(yscrollcommand=vsb_main.set)

# Shows details of SDP
details_frame = ttk.Frame(root)
details_frame.grid(row=0, column=2, pady=10, sticky="nsew")
# Shows sources of a domain
sources_frame = ttk.Frame(root)
sources_frame.grid(row=0, column=3, padx=5, sticky="s")

root.mainloop()

conn.close()
