# details.py
import tkinter as tk
import webbrowser
from tkinter import ttk
from sources import open_domain_table


# Store selected button and show confidence menu
def show_conf_menu(event, menu, button, cursor, conn, root):
    global selected_domain
    selected_domain = button
    menu.post(event.x_root, event.y_root)


# Change the color of a button to indicate confidence level
def change_conf(color, cursor, conn):
    selected_item = selected_domain.selection()

    # Update the color of the text in the selected item
    selected_domain.item(selected_item, tags=(color,))

    # Update database with the color information
    cursor.execute("""
        INSERT OR REPLACE INTO button_colors (button_name, color) VALUES (?, ?)
    """, (selected_domain.item(selected_item, "values")[0], color))

    conn.commit()


def show_details(name, sdp_url, class_key, problem, solution, known_uses, related_patterns, tags, root, cursor, conn):
    details_frame = ttk.Frame(root)
    details_frame.grid(row=0, column=2, padx=20, pady=10, sticky="nsew")

    ttk.Label(details_frame, text="Name:", font=("Arial", 10, "bold")).grid(row=0, column=0, pady=5, sticky="w")
    ttk.Label(details_frame, text=name).grid(row=0, column=2, pady=5, sticky="w")

    ttk.Label(details_frame, text="URL:", font=("Arial", 10, "bold")).grid(row=1, column=0, pady=5, sticky="w")
    url_label = tk.Label(details_frame, text=sdp_url, foreground="blue", wraplength=500, justify="left")
    url_label.grid(row=1, column=2, pady=5, sticky="w")
    url_label.bind("<Button-1>", lambda event, url=sdp_url: webbrowser.open(url))

    ttk.Label(details_frame, text="Class Key:", font=("Arial", 10, "bold")).grid(row=2, column=0, pady=5, sticky="w")
    ttk.Label(details_frame, text=class_key).grid(row=2, column=2, pady=5, sticky="w")

    ttk.Label(details_frame, text="Problem:", font=("Arial", 10, "bold")).grid(row=3, column=0, pady=5, sticky="w")
    problem_label = ttk.Label(details_frame, text=problem, wraplength=500, justify="left")
    problem_label.grid(row=3, column=2, pady=5, sticky="w")

    ttk.Label(details_frame, text="Solution:", font=("Arial", 10, "bold")).grid(row=4, column=0, pady=5, sticky="w")
    solution_label = ttk.Label(details_frame, text=solution, wraplength=500, justify="left")
    solution_label.grid(row=4, column=2, pady=5, sticky="w")

    ttk.Label(details_frame, text="Known Uses:", font=("Arial", 10, "bold")).grid(row=5, column=0, pady=5, sticky="w")
    known_uses_label = ttk.Label(details_frame, text=known_uses, wraplength=500, justify="left")
    known_uses_label.grid(row=5, column=2, pady=5, sticky="w")

    ttk.Label(details_frame, text="Related Patterns:", font=("Arial", 10, "bold")).grid(row=6, column=0, pady=5,
                                                                                        sticky="w")
    ttk.Label(details_frame, text=related_patterns).grid(row=6, column=2, pady=5, sticky="w")

    ttk.Label(details_frame, text="Tags:", font=("Arial", 10, "bold")).grid(row=7, column=0, pady=5, sticky="w")
    ttk.Label(details_frame, text=tags).grid(row=7, column=2, pady=5, sticky="w")

    domain_frame = ttk.Frame(root)
    domain_frame.grid(row=0, column=2, padx=5, sticky="s")
    domain_tree = ttk.Treeview(domain_frame, columns=("Domain",), show="headings", height=10)
    domain_tree.heading("Domain", text="Domains")
    domain_tree.column("Domain", width=600)

    # INSERT DOMAIN OPTIONS
    for domain in ["CVE", "NVD", "CWE"]:
        # Load confidence levels
        cursor.execute("SELECT color FROM button_colors WHERE button_name = ?", (domain,))
        result = cursor.fetchone()
        color = result[0] if result else "Default"

        domain_tree.insert("", "end", values=(domain,), tags=(color,))

    domain_tree.grid(row=8, column=2, pady=10, sticky="w")
    domain_tree.bind("<ButtonRelease-1>", lambda event: open_domain_table(
        domain_tree.item(domain_tree.selection(), "values")[0],
        f"{domain_tree.item(domain_tree.selection(), 'values')[0].lower()}_data", name, root, cursor))

    domain_tree.tag_configure("Green", background="Green3")
    domain_tree.tag_configure("Yellow", background="yellow")
    domain_tree.tag_configure("Red", background="firebrick1")

    # Create a context menu
    context_menu = tk.Menu(root, tearoff=0)
    context_menu.add_command(label="Change confidence: HIGH", command=lambda: change_conf("Green", cursor, conn))
    context_menu.add_command(label="Change confidence: MEDIUM", command=lambda: change_conf("Yellow", cursor, conn))
    context_menu.add_command(label="Change confidence: LOW", command=lambda: change_conf("Red", cursor, conn))

    domain_tree.bind("<Button-3>", lambda event: show_conf_menu(event, context_menu, domain_tree, cursor, conn, root))

