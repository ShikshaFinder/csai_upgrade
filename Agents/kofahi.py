import json
from agent import Agent

class Kofahi(Agent):
    def __init__(self, api_key, azure_endpoint=None, deployment_name=None):
        super().__init__("Kofahi", api_key, azure_endpoint, deployment_name)

    def handle_error(self, error_message, context, log_file_path=None):
        system_message = "You are Kofahi, an experienced and expert in Linux OS. Your role is to provide quick fixes and explanations for errors encountered during the execution of commands. Respond with the fix in JSON format, using the 'fix' key as an array of command strings to be executed in the correct order, and the 'explanation' key to provide the reason for the error and any necessary context."
        
        user_message = f"Error Message:\n{error_message}\n\nContext:\n{context}\n\nPlease provide a quick fix for the encountered error, along with an explanation of the reason for the error. Respond with the fix in JSON format, including any necessary commands to be executed in the correct order."
        
        kofahi_response = self.generate_response("Salah", user_message, system_message, response_format={"type": "json_object"})
        self.print_agent_output(text=kofahi_response, log_file_path=log_file_path)
        return json.loads(kofahi_response)