#!/usr/bin/env python3

from typing import *
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, messagebox

from socket import gethostname

from enum import Enum

class ScreenState(Enum):
    LOGIN = 0
    CHAT = 1

class ChatApp(ttk.Frame):
    def __init__(self, root, client) -> None:
        self.root = root
        self.root.title("Client")
        super().__init__(root, padding=10)

        self.message_box_content = ""
        self.client = client
        self.client.start(gethostname(), 8080)

        self.screen_state = ScreenState.LOGIN

        self.login()

    def changeState(self, new_state: ScreenState):
        # Limpar widgets atuais
        for widget in self.root.winfo_children():
            widget.destroy()

        match (new_state):
            case ScreenState.LOGIN.value:
                self.login()
            case ScreenState.CHAT.value:
                self.setupChatLayout()

        self.screen_state = new_state

    def login(self):
        """
        Layout da tela de login
        """

        tk.Label(self.root, text="Autentique-se", font=("Arial", 16)).grid(row=0, column=0, columnspan=2, pady=10)
        tk.Label(self.root, text="Usuário:").grid(row=1, column=0, pady=5)
        tk.Label(self.root, text="Senha:").grid(row=2, column=0, pady=5)

        self.username_box = tk.Entry(self.root)
        self.username_box.grid(row=1, column=1, pady=5)

        self.password_box = tk.Entry(self.root, show="*")
        self.password_box.grid(row=2, column=1, pady=5)

        self.login_button = tk.Button(self.root, text="Login", command=self.authenticateUser)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=10)

    def authenticateUser(self):
        login_success = self.client.authenticate(
            username = self.username_box.get(),
            passwd   = self.password_box.get()
        )

        title, msg = "A autenticação falhou", "Usuário ou senha inválidos!"
        if login_success:
            title, msg = "Bem vindo!", "Login realizado com sucesso!"

        messagebox.showinfo(title, msg)
        if login_success:
            self.setupChatLayout()
        
    def setupChatLayout(self):
        """
        Layout da tela de chat
        """

        self.chat_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state='disabled', height=20, width=50)
        self.chat_area.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        self.message_box = tk.Entry(self.root, width=40)
        self.message_box.grid(row=1, column=0, padx=10, pady=10)
        self.message_box.bind('<Return>', lambda e: self.sendMessage(e))

        self.send_button = tk.Button(self.root, text="Send", command=self.sendMessage)
        self.send_button.grid(row=1, column=1, padx=10, pady=10)

    def sendMessage(self, msg=None):
        if not msg:
            msg = self.message_box.get()

        if self.client.dst is not None:
            self.client.interpretMessage(msg)

if __name__ == "__main__":
    print("Para executar o GUI, por favor utilize o arquivo `run_client_gui.py`")
