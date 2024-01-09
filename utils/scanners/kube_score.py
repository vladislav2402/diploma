import json, subprocess


from ..commands.execute_command import run_command

def scan_cluster_kube_score():
    script_path = r'kube_score_cluster.sh'
    result = run_command(script_path)

    try:
        json_data = json.loads(result.stdout)
        return parse_kubescore_data(json_data)
    except json.JSONDecodeError:
        print("Error: Output is not valid JSON.")
        return None

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

    result_json = json.dumps(parsed_data, indent=4)
    return result_json

def parse_kubescore_output(filepath):
    try:
        result = subprocess.run(['kube-score', 'score', filepath, '-o', 'json'],
                                capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        return parse_kubescore_data(data)
    except:
        return json.dumps([], indent=4)