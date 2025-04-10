import json
import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Dict, List, Optional

class WebAuthAnalyzer:
    def __init__(self, api_key: str, azure_endpoint: str, deployment_name: str):
        self.api_key = api_key
        self.azure_endpoint = azure_endpoint
        self.deployment_name = deployment_name
        self.auth_requirements_file = "auth_requirements.json"
        self.temp_dir = os.getenv("TEMP_DIR", "/app/temp")

    def analyze_website(self, url: str) -> Dict:
        """Analyze website for authentication requirements and tokens."""
        print(f"[+] Analyzing website: {url}")
        
        try:
            # Initial request to get basic structure
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Initialize auth requirements structure
            auth_requirements = {
                "url": url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "requires_authentication": False,
                "auth_methods": [],
                "token_requirements": [],
                "cookie_requirements": [],
                "manual_steps": [],
                "agent_suggestions": [],
                "status": "pending"
            }
            
            # Check for common authentication forms
            auth_forms = soup.find_all('form')
            for form in auth_forms:
                if any(keyword in form.get('action', '').lower() for keyword in ['login', 'signin', 'auth']):
                    auth_requirements["requires_authentication"] = True
                    auth_requirements["auth_methods"].append("form_based")
                    
                    # Analyze form fields
                    form_fields = form.find_all('input')
                    for field in form_fields:
                        field_type = field.get('type', '')
                        field_name = field.get('name', '')
                        if field_type == 'password':
                            auth_requirements["token_requirements"].append({
                                "type": "password",
                                "name": field_name,
                                "required": True,
                                "obtained": False,
                                "instructions": "Enter your password in the login form"
                            })
                        elif field_type == 'text' and any(keyword in field_name.lower() for keyword in ['user', 'email', 'username']):
                            auth_requirements["token_requirements"].append({
                                "type": "username",
                                "name": field_name,
                                "required": True,
                                "obtained": False,
                                "instructions": "Enter your username/email in the login form"
                            })
            
            # Check for OAuth buttons
            oauth_buttons = soup.find_all('a', href=lambda x: x and any(provider in x.lower() for provider in ['google', 'facebook', 'github', 'oauth']))
            if oauth_buttons:
                auth_requirements["requires_authentication"] = True
                auth_requirements["auth_methods"].append("oauth")
                for button in oauth_buttons:
                    auth_requirements["token_requirements"].append({
                        "type": "oauth_token",
                        "provider": button.get('href', '').split('/')[-1],
                        "required": True,
                        "obtained": False,
                        "instructions": f"Click the {button.text.strip()} button to authenticate"
                    })
            
            # Add manual steps for token collection
            if auth_requirements["requires_authentication"]:
                auth_requirements["manual_steps"].extend([
                    {
                        "step": 1,
                        "description": "Open browser developer tools (F12)",
                        "location": "Browser"
                    },
                    {
                        "step": 2,
                        "description": "Go to Network tab",
                        "location": "Developer Tools"
                    },
                    {
                        "step": 3,
                        "description": "Perform login/signup",
                        "location": "Website"
                    },
                    {
                        "step": 4,
                        "description": "Look for authentication tokens in Network requests",
                        "location": "Network Tab"
                    },
                    {
                        "step": 5,
                        "description": "Check Application tab for cookies and local storage",
                        "location": "Developer Tools"
                    }
                ])
            
            # Generate agent suggestions
            self._generate_suggestions(auth_requirements)
            
            # Save requirements to file
            self._save_requirements(auth_requirements)
            
            return auth_requirements
            
        except Exception as e:
            print(f"Error analyzing website: {str(e)}")
            return {
                "url": url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(e),
                "status": "error"
            }

    def _generate_suggestions(self, auth_requirements: Dict) -> None:
        """Generate suggestions based on authentication requirements."""
        if auth_requirements["requires_authentication"]:
            # Add suggestions for form-based auth
            if "form_based" in auth_requirements["auth_methods"]:
                auth_requirements["agent_suggestions"].append({
                    "agent": "SQLInjectionTester",
                    "suggestion": "Test login form for SQL injection vulnerabilities",
                    "priority": "high"
                })
                auth_requirements["agent_suggestions"].append({
                    "agent": "BruteForceTester",
                    "suggestion": "Test login form for brute force protection",
                    "priority": "medium"
                })
            
            # Add suggestions for OAuth
            if "oauth" in auth_requirements["auth_methods"]:
                auth_requirements["agent_suggestions"].append({
                    "agent": "OAuthTester",
                    "suggestion": "Test OAuth implementation for security issues",
                    "priority": "high"
                })
            
            # Add general suggestions
            auth_requirements["agent_suggestions"].extend([
                {
                    "agent": "SessionTester",
                    "suggestion": "Test session management and token handling",
                    "priority": "high"
                },
                {
                    "agent": "CSRFTester",
                    "suggestion": "Test for CSRF protection in authenticated requests",
                    "priority": "high"
                }
            ])

    def _save_requirements(self, auth_requirements: Dict) -> None:
        """Save authentication requirements to JSON file."""
        with open(self.auth_requirements_file, 'w') as f:
            json.dump(auth_requirements, f, indent=2)

    def update_requirements(self, updates: Dict) -> None:
        """Update authentication requirements with obtained tokens or cookies."""
        try:
            with open(self.auth_requirements_file, 'r') as f:
                current_requirements = json.load(f)
            
            # Update token requirements
            for token in updates.get("tokens", []):
                for req in current_requirements["token_requirements"]:
                    if req["name"] == token["name"]:
                        req.update(token)
            
            # Update cookie requirements
            for cookie in updates.get("cookies", []):
                for req in current_requirements["cookie_requirements"]:
                    if req["name"] == cookie["name"]:
                        req.update(cookie)
            
            # Update status
            current_requirements["status"] = "updated"
            
            # Save updated requirements
            self._save_requirements(current_requirements)
            
            return current_requirements
            
        except Exception as e:
            print(f"Error updating requirements: {str(e)}")
            return None

    def get_requirements(self) -> Optional[Dict]:
        """Get current authentication requirements."""
        try:
            with open(self.auth_requirements_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"Error reading requirements: {str(e)}")
            return None 