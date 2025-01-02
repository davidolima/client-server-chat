from client import Cliente
from interface.chat import ChatApp

from tkinter import Tk

if __name__ == '__main__':
    root = Tk()
    client = Cliente()
    app = ChatApp(root, client)
    app.mainloop()
