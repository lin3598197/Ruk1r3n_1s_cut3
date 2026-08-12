import tkinter as tk

from proj.gui import SSTIOneClickGUI


def main():
    root = tk.Tk()
    app = SSTIOneClickGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
