#!/usr/bin/env python3

from typing import *
from enum import Enum

import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, messagebox, filedialog

from client import Cliente

class ScreenState(Enum):
    LOGIN = 0
    CHAT = 1

class App(ttk.Frame):
    def __init__(self, root: tk.Tk, client: Cliente, addr: str, port: int) -> None:
        self.root = root
        self.root.title("Client")
        super().__init__(root, padding=10)

        self.message_box_content = ""
        self.client = client
        self.client.start(addr, port)
        self.client.registerGUI(self)

        self.screen_state = ScreenState.LOGIN

        self.login()

    def changeState(self, new_state: ScreenState):
        # Limpar widgets atuais
        for widget in self.root.winfo_children():
            widget.destroy()

        match (new_state):
            case ScreenState.LOGIN:
                self.login()
            case ScreenState.CHAT:
                self.setupChatLayout()
            case _:
                raise RuntimeError(f"Request to change into unknown screen state: {new_state}")
        self.screen_state = new_state

    @staticmethod
    def bemVindo():
        msg  = ["-----------------------------------------\n"]
        msg += ["|        Bem vindo ao servidor          |\n"]
        msg += ["+---------------------------------------+\n"]
        msg += ["|  Este trabalho foi desenvolvido como  |\n"]
        msg += ["|  trabalho semestral para a disciplina |\n"]
        msg += ["|  de Redes de Computadores, ministrada |\n"]
        msg += ["|  pelo prof. Leobino Sampaio, no seme- |\n"]
        msg += ["|  stre de 2024.2, na Universidade Fe-  |\n"]
        msg += ["|  deral da Bahia.                      |\n"]
        msg += ["+---------------------------------------+\n"]
        msg += ["|           Membros do Grupo            |\n"]
        msg += ["+---------------------------------------+\n"]
        msg += ["|  Breno Nascimento da Silva Cupertino  |\n"]
        msg += ["|  David de Oliveira Lima               |\n"]
        msg += ["|  Ícaro Miranda de Santana             |\n"]
        msg += ["|  Yan Brandão Borges da Silva          |\n"]
        msg += ["-----------------------------------------\n"]
        return msg

    def login(self):
        """
        Layout da tela de login
        """

        tk.Label(self.root, text="Autentique-se", font=("Arial", 16)).grid(row=0, column=0, columnspan=4, pady=15)
        tk.Label(self.root, text="Usuário:").grid(row=1, column=0, pady=5, padx=5)
        tk.Label(self.root, text="Senha:").grid(row=2, column=0, pady=5, padx=5)

        self.username_box = tk.Entry(self.root)
        self.username_box.grid(row=1, column=1, columnspan=3, pady=5, padx=5)

        self.password_box = tk.Entry(self.root, show="*")
        self.password_box.grid(row=2, column=1, columnspan=3, pady=5, padx=5)

        self.register_button = tk.Button(self.root, text="Cadastrar", command=self.registerUser)
        self.register_button.grid(row=3, column=0, columnspan=2, pady=10, padx=5)

        self.login_button = tk.Button(self.root, text="Login", command=self.authenticateUser)
        self.login_button.grid(row=3, column=2, columnspan=2, pady=10, padx=5)
        self.login_button.bind('<Return>', lambda _: self.authenticateUser())


    def authenticateUser(self):
        usr = self.username_box.get()
        pwd = self.password_box.get()
        if not usr or not pwd:
            messagebox.showinfo("A autenticação falhou", "Por favor, preencha os dois campos.")
            return

        login_success = self.client.authenticate(usr, pwd)
        if login_success:
            self.changeState(ScreenState.CHAT)
            self.client.start_receive_loop()
            return

        messagebox.showinfo("A autenticação falhou", "Usuário ou senha inválidos!")

    def registerUser(self):
        usr = self.username_box.get()
        pwd = self.password_box.get()

        if not usr or not pwd:
            messagebox.showinfo("A autenticação falhou", "Por favor, preencha os dois campos.")
            return

        error_msg = self.client.registerUser(usr, pwd)
        if not error_msg:
            messagebox.showinfo("Usuário cadastrado com sucesso", "Agora você pode logar.")
            return

        messagebox.showinfo("Erro durante o cadastro", str(error_msg))

    def setupChatLayout(self):
        """
        Layout da tela de chat
        """

        self.root.title(self.client.getUsername())

        self.chat_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state='disabled')
        self.chat_area.grid(row=0, column=1, rowspan=2, columnspan=3, padx=10, pady=10)

        self.users_list = tk.Listbox(self.root, height=20, width=20)
        self.users_list.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky='ns')
        self.users_list.bind("<<ListboxSelect>>", self.selectDestinationUser)

        self.create_group_button = tk.Button(self.root, text="Criar grupo", command=self.getUsersForGroup)
        self.create_group_button.grid(row=2, column=0, padx=5, pady=10)

        self.message_box = tk.Entry(self.root, width=70)
        self.message_box.grid(row=2, column=1, padx=10, pady=10)
        self.message_box.bind('<Return>', lambda _: self.sendMessage())

        self.send_button = tk.Button(self.root, text="Enviar", command=self.sendMessage)
        self.send_button.grid(row=2, column=2, padx=5, pady=10)
        self.message_box.bind('<Return>', lambda _: self.sendMessage())

        self.send_file_button = tk.Button(self.root, text="+", command=self.sendFile)
        self.send_file_button.grid(row=2, column=3, padx=5, pady=10)

    def selectDestinationUser(self, event):
        selected = self.users_list.curselection()
        if selected:
            dst = self.users_list.get(selected[0]).replace(' *', '')
            self.client.setDestination(dst)

        self.update()

    def updateUsersList(self, users):
        self.users_list.delete(0, tk.END)  # Clear the list
        for user in users:
            self.users_list.insert(tk.END, user + (' *' if user in self.client.getUnread() else ''))

    def getUsersForGroup(self):
        select_group_root = tk.Tk()
        select_group_root.title("Criar novo grupo")

        new_group = []
        select_group_window = ttk.Frame(select_group_root, padding=100, height=250, width=300)

        group_name_box = tk.Entry(select_group_root)
        group_name_box.grid(row=0, column=0, padx=10, pady=10)

        users_list = tk.Listbox(select_group_root, activestyle='dotbox', selectmode='multiple')
        users_list.grid(row=1, column=0, padx=10, pady=10, sticky='ns')
        users_list.bind("<<ListboxSelect>>", lambda x: new_group.append(x))

        users_list.delete(0, tk.END)  # Clear the list
        for user in self.client.getCachedOnlineUsers():
            if user == self.client.getUsername():
                continue
            users_list.insert(tk.END, user + (' *' if user in self.client.getUnread() else ''))

        def createGroupButton():
            self.createGroup(group_name_box.get(), [users_list.get(i) for i in users_list.curselection()])
            select_group_root.destroy()

        create_group_button = tk.Button(select_group_root, text="Criar grupo", command=createGroupButton)
        create_group_button.grid(row=0, column=1, padx=5, pady=10)
        create_group_button.bind('<Return>', lambda _: self.sendMessage())

    def createGroup(self, name: str, users: list[str]):
        users.append(self.client.getUsername())
        self.client.createGroup(name, users)

    def sendFile(self):
        fname = filedialog.askopenfilename(
            title="Selecione um arquivo para enviar",
            initialdir='/'
        )
        self.client.sendFile(self.client.dst, fname)

    def sendMessage(self):
        msg = self.message_box.get()

        if self.client.dst is not None:
            self.client.interpretMessage(msg)

        self.message_box.delete(0, 'end')

    def displayMessages(self):
        self.clearChat()
        self.chat_area.config(state='normal')

        dst = self.client.getDestination()
        msgs = None
        if dst:
            self.chat_area.insert(tk.INSERT, f'Conversando com {self.client.getDestination()}')
            msgs = self.client.getMsgHistoryWithUsr(dst)
            for msg in msgs:
                self.chat_area.insert(tk.INSERT, '\n' + str(msg))
                self.chat_area.see(tk.END)
        else:
            msgs = App.bemVindo()
            for msg in msgs:
                self.chat_area.insert(tk.INSERT, str(msg))
                self.chat_area.see(tk.END)

        self.chat_area.config(state='disabled')

    def clearChat(self):
        self.chat_area.configure(state='normal')
        self.chat_area.delete('1.0', tk.END)
        self.chat_area.configure(state='disabled')

    def update(self):
        self.displayMessages()
        self.updateUsersList(self.client.getCachedOnlineUsers())

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default='localhost', type=str)
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()

    app = App(
        root   =   tk.Tk(),
        client = Cliente(),
        addr   = args.host,
        port   = args.port
    )
    app.mainloop()
