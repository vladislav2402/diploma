import json
from ..commands.execute_command import run_command

def scan_cluster_kube_scape():
    script_path = r'kubescape-cluster.sh'
    result = run_command(script_path)

    try:
        json_data = json.loads(result.stdout)
        return parse_kubescape_data(json_data)
    except json.JSONDecodeError:
        print("Error: Output is not valid JSON.")
        return None

def parse_kubescape_data(data):
    parsed_results = []
    for control_id, control_data in data['summaryDetails']['controls'].items():
        if control_data.get('status', '') == 'passed':
            continue

        vulnerability = control_data.get('name', 'Unknown Vulnerability')
        score = control_data.get('score', 0)

        if score >= 6:
            level = "error"
        elif score > 3:
            level = "warning"
        else:
            level = "info"

        result = {
            "vulnerability": vulnerability,
            "level": level,
            "message": vulnerability
        }

        parsed_results.append(result)
    result_json = json.dumps(parsed_results, indent=4)
    return result_json
