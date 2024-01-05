import os
import subprocess
from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
import json
# from openai import OpenAI
from datetime import datetime
import concurrent.futures

# client = OpenAI()

app = Flask(__name__)

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

app.config['UPLOAD_FOLDER'] = os.getcwd()
app.secret_key = 'your_secret_key'


def allowed_file_names(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'yaml', 'yml'}

def parse_kubeaudit_output(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    parsed_data = []
    for line in lines:
        try:
            item = json.loads(line)
            transformed_item = {
                "vulnerability": item["AuditResultName"],
                "level": item["level"],
                "message": item["msg"]
            }
            parsed_data.append(transformed_item)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")

    # Convert the parsed data to JSON
    result_json = json.dumps(parsed_data, indent=4)
    return result_json

def parse_kubescore_output(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)  # Load JSON content
        return parse_kubescore_data(data)
    except:
        return json.dumps([], indent=4)


def parse_kubescore_data(data):
    parsed_data = []
    for item in data:  # Iterate over the items in the JSON array
        checks = item.get("checks", [])

        for check in checks:
            vulnerability = check["check"]["name"]
            grade = check["grade"]
            message = check["check"]["comment"]

            # Determine the level based on the grade
            if grade >= 6:
                level = "error"
            elif grade > 3:
                level = "warning"
            else:
                level = "info"

            transformed_item = {
                "vulnerability": vulnerability,
                "level": level,
                "message": message
            }

            parsed_data.append(transformed_item)
    # Convert the parsed data to JSON
    result_json = json.dumps(parsed_data, indent=4)
    return result_json


def parse_kubescape_data(data):
    parsed_results = []
    for control_id, control_data in data['summaryDetails']['controls'].items():
        # Skip if the status is 'passed'
        if control_data.get('status', '') == 'passed':
            continue

        vulnerability = control_data.get('name', 'Unknown Vulnerability')
        score = control_data.get('score', 0)

        # Determine level based on score
        if score >= 6:
            level = "error"
        elif score > 3:
            level = "warning"
        else:
            level = "info"

        # Construct the formatted result
        result = {
            "vulnerability": vulnerability,
            "level": level,
            "message": vulnerability  # Assuming message is the same as the name
        }

        parsed_results.append(result)

    result_json = json.dumps(parsed_results, indent=4)
    return result_json


def parse_kubesec_output(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)  # Load JSON content

        parsed_data = []

        for item in data:
            critical_checks = item.get("scoring", {}).get("critical", [])
            for check in critical_checks:
                check_name = check["id"]
                message = check["reason"]

                transformed_item = {
                    "vulnerability": check_name,
                    "level": "error",
                    "message": message
                }

                parsed_data.append(transformed_item)

            # Process advise checks
            advise_checks = item.get("scoring", {}).get("advise", [])
            for check in advise_checks:
                check_name = check["id"]
                message = check["reason"]

                transformed_item = {
                    "vulnerability": check_name,
                    "level": "warning",
                    "message": message
                }

                parsed_data.append(transformed_item)

        # Convert the parsed data to JSON
        result_json = json.dumps(parsed_data, indent=4)

        return result_json
    except:
        return json.dumps([], indent=4)

def parse_datree_output(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)  # Load JSON content

        parsed_data = []

        # Iterate over policyValidationResults
        for result in data.get("policyValidationResults", []):
            # Iterate over the checks in each result
            for check in result.get("ruleResults", []):
                vulnerability = check.get("identifier", "")
                message = check.get("name", "")

                transformed_item = {
                    "vulnerability": vulnerability,
                    "level": "error",  # Default level is error
                    "message": message
                }

                parsed_data.append(transformed_item)

        # Convert the parsed data to JSON
        result_json = json.dumps(parsed_data, indent=4)

        return result_json
    except:
        return json.dumps([], indent=4);

def remove_duplicates(json_data):
    vulnerabilities_list_json = json.dumps(json_data)
    vulnerabilities_list = json.loads(vulnerabilities_list_json)

    vulnerabilities_list.sort(key=lambda x: len(x["vulnerability"]), reverse=True)

    unique_vulnerabilities = []

    while vulnerabilities_list:
        item = vulnerabilities_list.pop(0)
        vulnerability = item["vulnerability"]

        if not any(vulnerability in unique_vuln["vulnerability"] for unique_vuln in unique_vulnerabilities):
            unique_vulnerabilities.append(item)

    return json.dumps(unique_vulnerabilities, indent=4)


def parse_kubelinter_output(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)  # Load JSON content

        parsed_data = []

        for report in data.get("Reports", []):
            vulnerability = report.get("Diagnostic", {}).get("Message", "")
            remediation = report.get("Remediation", "")

            transformed_item = {
                "vulnerability": vulnerability,
                "level": "error",  # Default level is error
                "message": remediation
            }

            parsed_data.append(transformed_item)

        # Convert the parsed data to JSON
        result_json = json.dumps(parsed_data, indent=4)

        return result_json
    except:
        return json.dumps([], indent=4)


def concatenate_json_objects(*json_objects):
    combined_data = []
    for idx, json_obj in enumerate(json_objects):
        if isinstance(json_obj, str):
            try:
                json_obj = json.loads(json_obj)
            except json.JSONDecodeError as e:
                raise ValueError(f"Error decoding JSON string at index {idx}: {e}")

        if isinstance(json_obj, list):
            combined_data.extend(json_obj)
        else:
            raise TypeError(f"Provided JSON object at index {idx} is neither a string nor a list: {type(json_obj)}")

    return combined_data

def openai_advice(file_path, json):
    file_content = get_file_content(file_path)
    if json is not None and OPENAI_API_KEY is not None:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo-1106",
            response_format={ "type": "json_object" },
            messages=[
                {"role": "user", "content": f"There are vulnerabilities in configuration: f{file_content}. "
                                            f"Fix and provide an advice how to prevent this."
                                            f" Output must be in JSON format where advice is under key \"advice\", fixed config under \"config\" on code block"}
            ]
        )
        return response.choices[0].message.content
    else:
        return ""


def get_file_content(file_path):
    with open(file_path, 'r') as file:
        lines = [line.rstrip() for line in file]
    return lines

def process_file(file, upload_dir):
    if allowed_file_names(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)

        # Unique output filenames
        kubeaudit_output = f"kubeaudit_output_{filename}.txt"
        kubescore_output = f"kubescore_output_{filename}.txt"
        kubesec_output = f"kubesec_output_{filename}.txt"
        datree_output = f"datree_output_{filename}.txt"
        kubelinter_output = f"kubelinter_output_{filename}.txt"

        # Run external commands
        os.system(f'kubeaudit all -f "{filepath}" --no-color -p json > {kubeaudit_output}')
        os.system(f'kube-score score "{filepath}" -o json > {kubescore_output}')
        os.system(f'kubesec scan "{filepath}" > {kubesec_output}')
        os.system(f'datree test -o json "{filepath}" > {datree_output}')
        os.system(f'kube-linter --format=json lint "{filepath}" > {kubelinter_output}')

        # Parse the outputs
        kubeaudit_findings = parse_kubeaudit_output(kubeaudit_output)
        kubescore_findings = parse_kubescore_output(kubescore_output)
        kubesec_findings = parse_kubesec_output(kubesec_output)
        datree_findings = parse_datree_output(datree_output)
        kubelinter_findings = parse_kubelinter_output(kubelinter_output)

        combined_json_data = concatenate_json_objects(kubelinter_findings, datree_findings, kubesec_findings, kubescore_findings, kubeaudit_findings)
        unique_vulnerabilities_json = remove_duplicates(combined_json_data)
        unique_vulnerabilities = json.loads(unique_vulnerabilities_json)

        # Cleanup - delete the output files
        os.remove(kubeaudit_output)
        os.remove(kubescore_output)
        os.remove(kubesec_output)
        os.remove(datree_output)
        os.remove(kubelinter_output)
        
        return filename, unique_vulnerabilities
    else:
        return None

def run_command(script_path):
    git_bash_executable = r"C:\Program Files\Git\bin\bash.exe"
    return subprocess.run([git_bash_executable, script_path], capture_output=True, text=True)

def scanClusterKubeScore():
    script_path = r'kube_score_cluster.sh'
    result = run_command(script_path)

    try:
        json_data = json.loads(result.stdout)
        return json_data
    except json.JSONDecodeError:
        print("Error: Output is not valid JSON.")
        return None

def scanClusterKubescape():
    script_path = r'kubescape-cluster.sh'
    result = run_command(script_path)

    try:
        json_data = json.loads(result.stdout)
        return json_data
    except json.JSONDecodeError:
        print("Error: Output is not valid JSON.")
        return None

@app.route('/cluster', methods=['GET', 'POST'])
def scanCluster():
    try:
        pods_count_result = subprocess.run(['kubectl', 'get', 'pods', '--output', 'name'], capture_output=True,
                                           text=True)

        if not pods_count_result.stdout.strip():
            raise Exception("No pods found in the cluster")

        kubescape_scan_result = scanClusterKubescape()
        kubescape_findings = parse_kubescape_data(kubescape_scan_result)

        kube_score_result = scanClusterKubeScore()
        kubescore_findings = parse_kubescore_data(kube_score_result)

        combined_json_data = concatenate_json_objects(kubescore_findings, kubescape_findings)
        unique_vulnerabilities_json = remove_duplicates(combined_json_data)
        unique_vulnerabilities = json.loads(unique_vulnerabilities_json)

        return render_template('scan_output_cluster.html', json_data=unique_vulnerabilities)

    except Exception as e:
        flash(str(e), 'warning')
        return render_template('upload.html')

@app.route('/', methods=['GET', 'POST'])
def upload_files():
    if request.method == 'POST':
        uploaded_files = request.files.getlist('directory')
        date_str = datetime.now().strftime("scanning_%Y_%m_%d")
        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], date_str)

        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

        all_findings = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_file = {executor.submit(process_file, file, upload_dir): file for file in uploaded_files}
            for future in concurrent.futures.as_completed(future_to_file):
                result = future.result()
                if result:
                    filename, findings = result
                    all_findings[filename] = findings

        return render_template('scan_output.html', all_findings=all_findings)

    return render_template('upload.html')



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
