import json
import os
from datetime import datetime
from Agents.ammar import Ammar
from Agents.hassan import Hassan
from Agents.kofahi import Kofahi
from Agents.rakan import Rakan
from Agents.salah import Salah
from Agents.sajed import Sajed
from Agents.web_auth_analyzer import WebAuthAnalyzer
from scanner import OWASPScanner
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get Azure OpenAI configuration from environment variables
API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
AZURE_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
DEPLOYMENT_NAME = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")

if not all([API_KEY, AZURE_ENDPOINT, DEPLOYMENT_NAME]):
    raise ValueError("Missing required Azure OpenAI configuration in environment variables")

def initialize_log_file(target_ip, scan_description):
    log_directory = "./Logs"
    os.makedirs(log_directory, exist_ok=True)
    
    timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    log_file_name = f"log-{timestamp}.json"
    log_file_path = os.path.join(log_directory, log_file_name)
    
    log_data = {
        "target_ip": target_ip,
        "scan_description": scan_description,
        "output": []
    }
    
    with open(log_file_path, "w") as log_file:
        json.dump(log_data, log_file, indent=2)
    
    return log_file_path

def main():
    target_ip = "34.202.94.66"
    target_url = f"http://{target_ip}"  # Assuming HTTP, modify as needed
    scan_description = "Analyze the given target for any potential vulnerabilities. If any vulnerabilities are detected, identify the corresponding exploits and generate a comprehensive report detailing the findings. Clearly document the exploit, its impact, and the steps required to mitigate it. Additionally, demonstrate the exploit in a controlled manner to validate the vulnerability before presenting it to the client"
    log_file_path = initialize_log_file(target_ip, scan_description)
    
    # Initialize scanner and analyzer
    scanner = OWASPScanner(target_url=target_url, verbose=True)
    auth_analyzer = WebAuthAnalyzer(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME)
    
    # Initialize agents
    ammar = Ammar(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME)
    hassan = Hassan(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME)
    kofahi = Kofahi(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME)
    rakan = Rakan(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME)
    salah = Salah(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME)
    sajed = Sajed(api_key=API_KEY, azure_endpoint=AZURE_ENDPOINT, deployment_name=DEPLOYMENT_NAME)
    
    findings = []

    # Run WebAuthAnalyzer first
    print("Analyzing website authentication requirements...")
    auth_requirements = auth_analyzer.analyze_website(target_url)
    findings.append({"auth_requirements": auth_requirements})
    
    # Run OWASP scanner
    print("Running initial OWASP vulnerability scan...")
    initial_scan_results = scanner.get_standardized_output()
    findings.append({"initial_scan_results": initial_scan_results})
    
    # Generate initial exploit suggestions
    initial_exploit_suggestions = scanner.generate_exploit_suggestions()
    findings.append({"initial_exploit_suggestions": initial_exploit_suggestions})
    
    # Have Hassan review the initial scan results and auth requirements
    print("Hassan reviewing initial scan results and auth requirements...")
    hassan_initial_review = hassan.review_output(
        initial_scan_results, 
        scan_description, 
        auth_requirements=auth_requirements,
        log_file_path=log_file_path
    )
    findings.append({"hassan_initial_review": hassan_initial_review})
    
    # Generate strategy based on Hassan's review
    print("Generating strategy based on initial scan results and auth requirements...")
    strategy = ammar.generate_strategy(
        target_ip, 
        scan_description, 
        initial_scan_results=initial_scan_results,
        auth_requirements=auth_requirements,
        hassan_review=hassan_initial_review,
        log_file_path=log_file_path
    )
    findings.append({"strategy": strategy})

    while True:
        reviewed_strategy = hassan.review_strategy(strategy, scan_description, log_file_path=log_file_path)
        findings.append({"reviewed_strategy": reviewed_strategy})

        if reviewed_strategy["approved"]:
            # Run detailed OWASP scanner with specific focus areas
            print("Running detailed OWASP vulnerability scan...")
            detailed_scan_results = scanner.get_standardized_output()
            findings.append({"detailed_scan_results": detailed_scan_results})
            
            # Generate detailed exploit suggestions
            detailed_exploit_suggestions = scanner.generate_exploit_suggestions()
            findings.append({"detailed_exploit_suggestions": detailed_exploit_suggestions})
            
            # Generate mitigation report
            mitigation_report = scanner.generate_mitigation_report()
            findings.append({"mitigation_report": mitigation_report})
            
            print("Hassan's Thoughts on the detailed scan result:")
            hassan_assessment = hassan.review_output(
                detailed_scan_results, 
                scan_description, 
                auth_requirements=auth_requirements,
                log_file_path=log_file_path
            )
            findings.append({"hassan_assessment": hassan_assessment})

            if hassan_assessment["satisfactory"]:
                print("Scan completed. Client's requirements have been met.")
                break
            else:
                feedback = hassan_assessment["feedback"]
                strategy = ammar.generate_strategy(
                    target_ip, 
                    scan_description, 
                    feedback=feedback,
                    previous_scan_results=detailed_scan_results,
                    auth_requirements=auth_requirements,
                    log_file_path=log_file_path
                )
                findings.append({"updated_strategy_based_on_feedback": strategy})
                print("Updated strategy based on Hassan's feedback:")
        else:
            feedback = reviewed_strategy["feedback"]
            print("Hassan's feedback:")
            print("Updated strategy based on Hassan's feedback:")
            strategy = ammar.generate_strategy(
                target_ip, 
                scan_description, 
                feedback=feedback,
                previous_scan_results=initial_scan_results,
                auth_requirements=auth_requirements,
                log_file_path=log_file_path
            )
            findings.append({"updated_strategy_based_on_feedback": strategy})

    findings_file = "findings.json"
    with open(findings_file, "w") as f:
        json.dump(findings, f, indent=2)

    print("Findings Report:")
    report = sajed.generate_report(target_ip, scan_description, findings_file, log_file_path=log_file_path)

    while True:
        hassan_review = hassan.review_report(report, log_file_path=log_file_path)
        findings.append({"hassan_review": hassan_review})
        print("Hassan's Review:")
        if hassan_review["Report Approval"]:
            print("Findings report has been approved by Hassan.")
            break
        else:
            feedback = hassan_review["feedback"]
            print("Hassan's feedback:")
            report = sajed.generate_report(target_ip, scan_description, findings_file, feedback=feedback, log_file_path=log_file_path)
            print("Updated Findings Report:")

    report_file = "findings_report.md"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"Findings report saved as {report_file}")

if __name__ == '__main__':
    main()
