import json
from agent import Agent

class Sajed(Agent):
    def __init__(self, api_key, azure_endpoint=None, deployment_name=None):
        super().__init__("Sajed", api_key, azure_endpoint, deployment_name)

    def generate_report(self, target_ip, scan_description, findings_file, feedback=None, log_file_path=None):
        with open(findings_file, "r") as f:
            findings = json.load(f)

        system_message = "You are Sajed, an expert findings report writer. Your role is to generate a comprehensive and professional findings report based on the provided JSON file containing the vulnerability scan findings. The report should include an appropriate title, an executive summary, detailed findings for each vulnerability, and recommendations for remediation. Structure the report in a clear and concise manner, using Markdown formatting."
        
        user_message = f"Target IP: {target_ip}\nScan Description: {scan_description}\nFindings File: {json.dumps(findings, indent=2)}\n\nPlease generate a comprehensive findings report based on the provided vulnerability scan findings. Use Markdown formatting for the report."
        
        if feedback:
            user_message += f"\n\nFeedback from Hassan: {feedback}\n\nPlease update the findings report based on the provided feedback, ensuring that the report is comprehensive, professional, and addresses all the necessary aspects."

        report = self.generate_response("Hassan", user_message, system_message)
        self.add_to_chat_history("Hassan", "user", user_message)
        self.add_to_chat_history("Hassan", "assistant", report)
        self.print_agent_output(text=report, log_file_path=log_file_path)
        return report.strip()