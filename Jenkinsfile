pipeline {
    agent any

    stages {

        stage('Checkout') {
            steps {
                git url: 'https://github.com/Fatima-295/SSD-Lab12.git', branch: 'main'
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarServer') {
                    bat """
                    D:\\ssd\\sonar-scanner-cli-7.3.0.5189-windows-x64\\sonar-scanner-7.3.0.5189-windows-x64\\bin\\sonar-scanner.bat ^
                    -Dsonar.projectKey=myproject ^
                    -Dsonar.sources=. ^
                    -Dsonar.host.url=%SONAR_HOST_URL% ^
                    -Dsonar.login=%SONAR_AUTH_TOKEN%
                    """
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 3, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Build') {
            steps {
                echo "Build completed"
            }
        }
    }
}
