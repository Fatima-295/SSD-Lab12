pipeline {
    agent any

    environment {
        SONAR_SERVER = 'SonarQubeServer'
    }

    stages {
        stage('Checkout') {
            steps {
                git url: 'https://github.com/<your-username>/<your-repo>.git'
            }
        }

        stage('Build') {
            steps {
                sh 'mvn clean install -DskipTests'
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv("${SONAR_SERVER}") {
                    sh '''
                        mvn sonar:sonar \
                        -Dsonar.projectKey=my-app \
                        -Dsonar.projectName=my-app \
                        -Dsonar.host.url=http://localhost:9000
                    '''
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
    }
}
