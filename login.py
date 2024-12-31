import json
import hashlib

class Login:
    """
        Classe que será utilizada para realização do login, cadastro e autenticação dos usuários.
    """

    # Arquivo JSON que será utilizado para salvar as informações de login e senha dos usuários
    USERS_FILE = "users.json"

    def __init__(self):
        self.username = None
        
    def getUsername(self):
        return self.username


    @staticmethod
    def hash_password(password):
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    
    def load_users(cls):
        """Load the user data from the JSON file."""
        try:
            with open(cls.USERS_FILE, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    
    def save_users(cls, users):
        """Save the user data to the JSON file."""
        with open(cls.USERS_FILE, 'w') as file:
            json.dump(users, file, indent=4)

    def register_user(self, username, password):
        """Register a new user."""
        users = self.load_users()

        if username in users:
            print()
            print("O nome de usuário escolhido já está em uso !")
            return False

        hashed_password = self.hash_password(password)
        users[username] = hashed_password
        self.save_users(users)
        self.username = username
        print("Usuário registrado com sucesso !")
        return True

    def authenticate_user(self, username, password):
        """Authenticate a user."""
        users = self.load_users()

        if username not in users:
            print()
            print("Usuário não encontrado !")
            return False

        hashed_password = self.hash_password(password)
        if users[username] == hashed_password:
            self.username = username
            print("Autenticação bem sucedida !")
            return True
        else:
            print()
            print("Senha Incorreta !")
            return False



    def interfaceAutenticacao(self):
        
        print("\n--- Sistema de Autenticação ! ---")
        print("1. Registrar-se")
        print("2. Logar")
        choice = input("Escolha uma opção: ")
            
        if choice == "1":
            username = input("Digite um nome de usuário: ")
            password = input("Digite uma senha: ")
            self.register_user(username, password)
        elif choice == "2":
            username = input("Digite um nome de usuário: ")
            password = input("Digite uma senha: ")
            self.authenticate_user(username, password)
        else:
            print("Opção inválida !")