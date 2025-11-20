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
                bat '"D:\\sonar-scanner\\bin\\sonar-scanner.bat" -v'
            }
        }
    }
}
