pipeline {
    agent any
    stages {
        stage('Test Echo') {
            steps {
                echo 'Hello, Jenkins is running!'
            }
        }

        stage('Test Scanner') {
            steps {
                bat '"D:\sonar-scanner-cli-7.3.0.5189-windows-x64\sonar-scanner-7.3.0.5189-windows-x64\bin\sonar-scanner.bat" -v'
            }
        }
    }
}
