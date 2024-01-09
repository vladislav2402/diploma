import json, subprocess


def parse_kubesec_output(filepath):

    try:
        result = subprocess.run(['kubesec', 'scan', filepath],
                                capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

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

        return json.dumps(parsed_data, indent=4)
    except:
        return json.dumps([], indent=4)
