# sources.py
from tkinter import ttk
import webbrowser


# Get all data from specific domain(e.g  table in db
def fetch_domain_data(domain_name, cursor):
    query = f"SELECT * FROM {domain_name}"
    cursor.execute(query)
    datatable = cursor.fetchall()
    return datatable


# Open a domain table and search for specific sdp in that table
def open_domain_table(domain_name, table_name, sdp_name, root, cursor):
    sources_frame = ttk.Frame(root)
    sources_frame.grid(row=0, column=3, padx=5, sticky="s")

    sources_label = ttk.Label(sources_frame, text=f"{domain_name} Results for {sdp_name}", font=("Arial", 11, "bold"))
    sources_label.grid(row=0, column=0, columnspan=3, sticky="n")

    sources_data = fetch_domain_data(table_name, cursor)
    sources_tree = ttk.Treeview(sources_frame, columns=("Rank", f"{domain_name} ID", f"{domain_name} URL"),
                                show="headings", height=33)

    sources_tree.heading("Rank", text="Rank")
    sources_tree.heading(f"{domain_name} ID", text=f"{domain_name} ID")
    sources_tree.heading(f"{domain_name} URL", text=f"{domain_name} URL")

    # For the domain table, only get the elements with matching name to search name
    for source in sources_data:
        if source[1] == sdp_name:
            sources_tree.insert("", "end", values=(source[0], source[4], source[5]))

    sources_tree.column("Rank", width=40)
    sources_tree.column(f"{domain_name} ID", width=100)
    sources_tree.column(f"{domain_name} URL", width=380)

    # When clicked, naviagte to url in source
    sources_tree.bind("<ButtonRelease-1>",
                      lambda event: webbrowser.open(sources_tree.item(sources_tree.selection(), "values")[2]))

    sources_tree.grid(row=2, column=0, pady=10, sticky="nsew")

    # Vertical scroll bar
    vsb_sources = ttk.Scrollbar(root, orient="vertical", command=sources_tree.yview)
    vsb_sources.grid(row=0, column=4, sticky="ns")
    sources_tree.configure(yscrollcommand=vsb_sources.set)