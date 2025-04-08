from openai import AzureOpenAI
from colorama import init, Fore, Style
import json
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

class Agent:
    def __init__(self, name=None, api_key=None, azure_endpoint=None, deployment_name=None):
        # Use environment variables if parameters are not provided
        self.name = name or os.getenv('AGENT_NAME')
        self.deployment_name = deployment_name or os.getenv('AZURE_OPENAI_DEPLOYMENT_NAME')
        self.client = AzureOpenAI(
            api_key=api_key or os.getenv('AZURE_OPENAI_API_KEY'),
            api_version="2024-02-15-preview",  # Use the latest API version
            azure_endpoint=azure_endpoint or os.getenv('AZURE_OPENAI_ENDPOINT')
        )
        self.chat_histories = {}

    def get_chat_history(self, recipient):
        if recipient not in self.chat_histories:
            self.chat_histories[recipient] = [
                {"role": "system", "content": f"You are {self.name}, an AI agent. You are communicating with {recipient}."},
            ]
        return self.chat_histories[recipient]

    def add_to_chat_history(self, recipient, role, content):
        chat_history = self.get_chat_history(recipient)
        chat_history.append({"role": role, "content": content})

    def print_agent_output(self, text=None, log_file_path=None):
        color = {
            "Ammar": Fore.BLUE,
            "Hassan": Fore.GREEN,
            "Kofahi": Fore.LIGHTGREEN_EX,
            "Rakan": Fore.MAGENTA,
            "Salah": Fore.YELLOW,
            "Sajed": Fore.CYAN,
            "Output": Fore.RED
        }.get(self.name, Fore.RESET)
        
        print(f"{color}{self.name}:{Style.RESET_ALL}")
        
        if text:
            try:
                data = json.loads(text)
                for key, value in data.items():
                    formatted_key = key.capitalize()
                    if isinstance(value, bool):
                        formatted_value = "Yes" if value else "No"
                    elif isinstance(value, list):
                        formatted_value = ", ".join(value)
                    else:
                        formatted_value = value
                    print(f"{color}{formatted_key}: {formatted_value}{Style.RESET_ALL}")
            except json.JSONDecodeError:
                print(f"{color}Text: {text}{Style.RESET_ALL}")
        
        print()

        log_entry = {
            "agent_name": self.name,
            "text": text
        }
        
        if log_file_path:
            with open(log_file_path, "r+") as log_file:
                log_data = json.load(log_file)
                log_data["output"].append(log_entry)
                log_file.seek(0)
                json.dump(log_data, log_file, indent=2)
                log_file.truncate()

    def generate_chat_messages(self, recipient, system_message, user_message):
        chat_history = self.get_chat_history(recipient)
        messages = [
            {"role": "system", "content": system_message},
            *chat_history[-10:],
            {"role": "user", "content": user_message}
        ]
        return messages

    def generate_response(self, recipient, user_message, system_message, response_format=None):
        chat_history = self.get_chat_history(recipient)
        self.add_to_chat_history(recipient, "user", user_message)
        messages = [
            {"role": "system", "content": system_message},
            *chat_history,
            {"role": "user", "content": user_message}
        ]
        if response_format:
            response = self.client.chat.completions.create(
                model=self.deployment_name,  # Use the Azure deployment name
                response_format=response_format,
                messages=messages
            )
        else:
            response = self.client.chat.completions.create(
                model=self.deployment_name,  # Use the Azure deployment name
                messages=messages
            )
        assistant_response = response.choices[0].message.content
        self.add_to_chat_history(recipient, "assistant", assistant_response)
        return assistant_response