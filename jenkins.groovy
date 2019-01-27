pipeline {
   agent any
   environment {
          SMART_CHECK_SERVER="dssc.bryceindustries.net"
          AWS_REGION="us-east-2"
          SCAN_REGISTRY="650143975734.dkr.ecr.us-east-2.amazonaws.com"
          SCAN_REPOSITORY="web-app"
          SMART_CHECK_CREDS=credentials('smart_check_jaws_world')
          AWS=credentials('ecr_aws')
          SCAN_ID="xxx"
    }
    stages
    {
        stage('Checkout') { // for display purposes
           steps{
                sh 'printenv'
                checkout([$class: 'GitSCM', branches: [[name: '*/master']], doGenerateSubmoduleConfigurations: false, extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'smart-check']], submoduleCfg: [], userRemoteConfigs: [[url: 'https://github.com/tsheth/docker-vulnerable-dvwa.git']]])
            }
        }
        stage('Build') {
            steps{
                sh("docker build -t $SCAN_REGISTRY/$JOB_BASE_NAME:$BUILD_ID $WORKSPACE/smart-check")
            }
        }
        stage('Send to Repository') {
              steps{
                  script{
                      sh("eval \$(aws ecr get-login --region us-east-2 --no-include-email | sed 's|https://||')")
                      sh("docker push $SCAN_REGISTRY/$JOB_BASE_NAME:$BUILD_ID")
                  }

            }
        }
        stage('Scan for Malware and Vulnerabilities')
        {
            steps{
                script {
                    def SCAN_ID = sh (
                        script: "python3 smart-check/scans_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}'  --scan_registry='${SCAN_REGISTRY}'  --scan_repository='${JOB_BASE_NAME}'  --scan_tag='${BUILD_ID}'  --aws_region='${AWS_REGION}'  --aws_id='${AWS_USR}'  --aws_secret='${AWS_PSW}'",
                        returnStdout: true
                    ).trim()

                    echo "SCAN_ID print: ${SCAN_ID}"

                    for (int i = 0; i < 120; i++) {
                            def index = i
                            def SCAN_RESULT = sh (
                                script: "python3 smart-check/status_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}' --scan_id=${SCAN_ID} --output='status'",
                                returnStdout: true
                            ).trim()
                            echo "${SCAN_RESULT}"

                            if("${SCAN_RESULT}" == "completed-with-findings")
                            {

                               break;
                            }
                            sh 'sleep 60'

                    }
                    def SCAN_VULNERABILITY = sh (
                                script: "python3 smart-check/status_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}' --scan_id=${SCAN_ID} --output='vulnerability'",
                                returnStdout: true
                             )


                    def SCAN_MALWARE = sh (
                                script: "python3 smart-check/status_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}' --scan_id=${SCAN_ID} --output='malware'",
                                returnStdout: true
                             )

                    def SCAN_CONTENT = sh (
                                script: "python3 smart-check/status_v2.py  --smart_check_url='${SMART_CHECK_SERVER}'  --smart_check_userid='${SMART_CHECK_CREDS_USR}'  --smart_check_password='${SMART_CHECK_CREDS_PSW}' --scan_id=${SCAN_ID} --output='contents'",
                                returnStdout: true
                             )
                    echo "Secret Found: ${SCAN_CONTENT}"
                    echo "Malware Result: ${SCAN_MALWARE}"
                    echo "Vulnerability Result: ${SCAN_VULNERABILITY}"

                    if("${SCAN_MALWARE}" != "" || "${SCAN_VULNERABILITY}" != "" || "${SCAN_CONTENT}" != "")
                    {
                        slackSend message: "Job: ${env.JOB_NAME} with buildnumber ${env.BUILD_NUMBER} was not deployed because there was malicious file or vulnerability detected. For more details visit (<${env.BUILD_URL}|Open>)"
                        echo "[FAILURE] Malware/Vulnerability or Secrets Found in image"
                        currentBuild.result = 'FAILURE'
                        sh "exit ${result}"
                    }
                }
            }
        }
        stage('Certify Release')
        {
            steps{
                sh ("docker tag $SCAN_REGISTRY/$JOB_BASE_NAME:$BUILD_ID $SCAN_REGISTRY/$JOB_BASE_NAME:latest")
            }
        }
        stage('Deploy to Production')
        {
            steps{
                sh ("docker push $SCAN_REGISTRY/$JOB_BASE_NAME:latest")
            }

        }
    }
}