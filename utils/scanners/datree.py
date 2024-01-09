import json, subprocess


def parse_datree_output(filepath):
    try:
        result = subprocess.run(['datree', 'test', '-o', 'json', filepath],
                                capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        parsed_data = []
        for result in data.get("policyValidationResults", []):
            for check in result.get("ruleResults", []):
                vulnerability = check.get("identifier", "")
                message = check.get("name", "")
                transformed_item = {
                    "vulnerability": vulnerability,
                    "level": "error",
                    "message": message
                }
                parsed_data.append(transformed_item)
        result_json = json.dumps(parsed_data, indent=4)
        return result_json
    except:
        return json.dumps([], indent=4)