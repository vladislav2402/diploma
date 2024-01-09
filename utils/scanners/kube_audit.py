import json, subprocess


def parse_kubeaudit_output(filepath):
    try:
        result = subprocess.run(['kubeaudit', 'all', '-f', filepath, '--no-color', '-p', 'json'],
                                capture_output=True, text=True, check=True)
        output = result.stdout

        parsed_data = []
        for line in output.splitlines():
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

        return json.dumps(parsed_data, indent=4)
    except:
        return json.dumps([], indent=4)
