import json, subprocess


def parse_kubelinter_output(filepath):
    try:
        result = subprocess.run(['kube-linter', '--format=json', 'lint', filepath],
                                capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

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