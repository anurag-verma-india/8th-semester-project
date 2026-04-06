pipeline {
    agent { label 'Agent43' }

    environment {
        REPORT_DIR = "reports"
        IMAGE_NAME = "node-app:scan"
    }

    stages {

        stage('Checking system') {
            steps {
                sh 'ip a'
            }
        }

        stage('Prepare Reports Directory') {
            steps {
                sh '''
                    rm -rf $REPORT_DIR
                    mkdir -p $REPORT_DIR
                '''
            }
        }

        stage('Build Docker Image (for container scans)') {
            steps {
                sh '''
                    docker build -t $IMAGE_NAME .
                '''
            }
        }

        stage('Run Hadolint (Dockerfile scan)') {
            steps {
                sh '''
                    hadolint -f json Dockerfile > $REPORT_DIR/hadolint.json || true
                '''
            }
        }

        stage('Run Semgrep (SAST)') {
            steps {
                sh '''
                    semgrep scan --config auto --json > $REPORT_DIR/semgrep.json || true
                '''
            }
        }

        stage('Run Gitleaks (Secrets scan)') {
            steps {
                sh '''
                    gitleaks detect --source . --report-format json --report-path $REPORT_DIR/gitleaks.json || true
                '''
            }
        }

        stage('Run Trivy (Filesystem scan)') {
            steps {
                sh '''
                    trivy fs . --format json --output $REPORT_DIR/trivy-fs.json || true
                '''
            }
        }

        stage('Run Syft (SBOM generation)') {
            steps {
                sh '''
                    syft . -o json > $REPORT_DIR/syft-sbom.json || true
                '''
            }
        }

        stage('Run Grype (Vulnerability scan from SBOM)') {
            steps {
                sh '''
                    grype sbom:$REPORT_DIR/syft-sbom.json -o json > $REPORT_DIR/grype.json || true
                '''
            }
        }

        stage('Run Trivy (Image scan)') {
            steps {
                sh '''
                    trivy image $IMAGE_NAME --format json --output $REPORT_DIR/trivy-image.json || true
                '''
            }
        }

        stage('Upload to DefectDojo') {
            steps {
                withCredentials([string(credentialsId: 'defect-dojo-api-key-agent43', variable: 'DD_API_KEY')]) {
                    sh '''
                        DD_URL="http://192.168.56.43:8085"
                        DD_PRODUCT="node-todo"
                        DD_ENGAGEMENT="Build-${BUILD_NUMBER}"

                        upload() {
                            SCAN_TYPE="$1"
                            FILE="$2"
                            if [ ! -s "$FILE" ]; then
                                echo "Skipping $FILE (empty or missing)"
                                return
                            fi
                            echo "Uploading $FILE as '$SCAN_TYPE'..."
                            curl -s -o /tmp/defectdojo-response.txt -w "%{http_code}" -X POST \
                                "${DD_URL}/api/v2/import-scan/" \
                                -H "Authorization: Token ${DD_API_KEY}" \
                                -F "scan_type=${SCAN_TYPE}" \
                                -F "file=@${FILE}" \
                                -F "product_name=${DD_PRODUCT}" \
                                -F "engagement_name=${DD_ENGAGEMENT}" \
                                -F "auto_create_context=true" \
                                -F "active=true" \
                                -F "verified=false" \
                                -F "close_old_findings=false" && echo " -> $FILE uploaded"
                        }

                        upload "Hadolint Dockerfile check" "$REPORT_DIR/hadolint.json"
                        upload "Semgrep JSON Report"        "$REPORT_DIR/semgrep.json"
                        upload "Gitleaks Scan"             "$REPORT_DIR/gitleaks.json"
                        upload "Trivy Scan"                "$REPORT_DIR/trivy-fs.json"
                        upload "Trivy Scan"                "$REPORT_DIR/trivy-image.json"
                        upload "Anchore Grype"             "$REPORT_DIR/grype.json"
                    '''

                    sh '''
                    cat /tmp/defectdojo-response.txt
                    '''
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', fingerprint: true
        }
    }
}
