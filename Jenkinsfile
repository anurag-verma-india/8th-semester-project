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
                    hadolint Dockerfile > $REPORT_DIR/hadolint.txt || true
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
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', fingerprint: true
        }
    }
}
