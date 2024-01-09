import os, json
from .file_validation import allowed_file_names
from werkzeug.utils import secure_filename
from utils.json_utils import concatenate_json_objects, remove_duplicates

from .scanners.kube_score import parse_kubescore_output
from .scanners.kube_audit import parse_kubeaudit_output
from .scanners.kube_linter import parse_kubelinter_output
from .scanners.kubesec import parse_kubesec_output
from .scanners.datree import parse_datree_output


def process_file(file, upload_dir):
    if allowed_file_names(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)

        # Parse the outputs
        kubeaudit_findings = parse_kubeaudit_output(filepath)
        kubescore_findings = parse_kubescore_output(filepath)
        kubesec_findings = parse_kubesec_output(filepath)
        datree_findings = parse_datree_output(filepath)
        kubelinter_findings = parse_kubelinter_output(filepath)

        combined_json_data = concatenate_json_objects(kubelinter_findings, datree_findings, kubesec_findings,
                                                      kubescore_findings, kubeaudit_findings)
        unique_vulnerabilities_json = remove_duplicates(combined_json_data)
        unique_vulnerabilities = json.loads(unique_vulnerabilities_json)
        return filename, unique_vulnerabilities
    else:
        return None