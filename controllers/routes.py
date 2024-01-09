import concurrent.futures
import json
import os
import subprocess

from flask import request, render_template, flash
from datetime import datetime
from models.models import ScanResult, db
from utils.file_reader import process_file
from utils.scanners.kube_score import scan_cluster_kube_score
from utils.scanners.kube_scape import scan_cluster_kube_scape
from utils.json_utils import concatenate_json_objects, remove_duplicates


def register_routes(app):
    @app.route('/cluster', methods=['GET', 'POST'])
    def scanCluster():
        try:
            pods_count_result = subprocess.run(['kubectl', 'get', 'pods', '--output', 'name'], capture_output=True,
                                               text=True)

            if not pods_count_result.stdout.strip():
                raise Exception("No pods found in the cluster")

            kubescape_findings = scan_cluster_kube_scape()
            kubescore_findings = scan_cluster_kube_score()

            combined_json_data = concatenate_json_objects(kubescore_findings, kubescape_findings)
            unique_vulnerabilities_json = remove_duplicates(combined_json_data)
            unique_vulnerabilities = json.loads(unique_vulnerabilities_json)

            return render_template('scan_output_cluster.html', json_data=unique_vulnerabilities)

        except Exception as e:
            flash(str(e), 'warning')
            return render_template('upload.html')

    @app.route('/scans', methods=['GET'])
    def get_scans():
        scans = ScanResult.query.all()
        scan_list = []
        for scan in scans:
            scan_dict = {
                'id': scan.id,
                'folder': scan.folder,
                'scan_result': scan.scan_result,  # Assuming this is already in a serializable format
                'timestamp': scan.timestamp.isoformat()  # Convert datetime to string
            }
            scan_list.append(scan_dict)
        return render_template('scan_history.html', scan_history=scan_list)

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
            new_scan = ScanResult(folder=upload_dir, scan_result=all_findings)
            db.session.add(new_scan)
            db.session.commit()
            return render_template('scan_output.html', all_findings=all_findings)

        return render_template('upload.html')