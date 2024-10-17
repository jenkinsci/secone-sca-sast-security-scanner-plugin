# Sec1 Security Scanner

[![Sec1](https://digitalassets.sec1.io/sec1-logo.svg)](https://sec1.io)

## Introduction

The Sec1 Security plugin provides both SCA and SAST capabilities, enabling teams to scan SCM repositories for open-source vulnerabilities and analyze code to detect security issues early in development.

## Usage
To use the plugin up you will need to take the following steps in order:

1. [Install the Sec1 Security Plugin](#1-install-the-sec1-security-plugin)
2. [Configure a Sec1 API Token Credential](#2-configure-a-sec1-api-token-credential)
3. [Add Sec1 Security to your Project](#3-add-sec1-security-to-your-project)

## 1. Install the SEC1 Security Scanner Plugin

- Go to "Manage Jenkins" > "System Configuration" > "Plugins".
- Search for "Sec1 Security Scanner" under "Available plugins".
- Install the plugin.

### Custom API Endpoints

By default, Sec1 uses the https://api.sec1.io endpoint. 
It is possible to configure Sec1 to use a different endpoint by changing the `SEC1_INSTANCE_URL` environment variable:

- Go to "Manage Jenkins" > "System Configuration" -> "System"
- Under "Global properties" check the "Environment variables" option
- Click "Add"
- Set the name to `SEC1_INSTANCE_URL` and the value to the custom endpoint


## 2. Configure a Sec1 API Token Credential

- Go to "Manage Jenkins" > "Security" > "Credentials"
- Choose a Store
- Choose a Domain
- Go to "Add Credentials"
- Select "Secret text"
- Add `<YOUR_SEC1_API_KEY_ID>` as ID and Configure the Credentials.
- Remember the "ID" as you'll need it when configuring the build step.

To get `Sec1 Api Key` navigate to [My Account](https://account.sec1.io/) > "Login with GitHub" > Click on profile icon at top right > "Settings"  
- In "API key" section, click on "Generate API key"
- Copy key for use.

<blockquote>
<details>
<summary>📷 Show Preview</summary>

![Sec1 API Token](docs/sec1-configuration-api-key.png)

</details>
</blockquote>

## 3. Add Sec1 Security to your Project

This step will depend on if you're using Freestyle Projects or Pipeline Projects.

### Freestyle Projects

- Select a project
- Go to "Configure"
- Under "Build", select "Add build step" select "Execute Sec1 Security Scanner"
- Configure as needed. Click the "?" icons for more information about each option.

<blockquote>
<details>
<summary>📷 Show Preview</summary>

![Basic configuration](docs/sec1-buildstep.png)

</details>
</blockquote>

### Pipeline Projects

Use the `sec1Security` step as part of your pipeline script. You can use the "Snippet Generator" to generate the code
from a web form and copy it into your pipeline.

<blockquote>
<details>
<summary>📷 Show Example</summary>

```groovy
pipeline {
  agent any

  stages {
    stage('Build') {
      steps {
        echo 'Building...'
      }
    }
    stage('Sec1 Sca Sast Security Scan') {
            steps {
                script {
                    sec1ScaSastSecurity (
                        scanFileLocation: "${WORKSPACE}", // this is the location of you scm checkout directory. if not configured don't change it.
                        apiCredentialsId: "<Your Sec1 Api Key ID>", 
                        //optional
                        runSec1SastSecurity: true,
                        applyThreshold: true,
                        actionOnThresholdBreached: "unstable",
                        threshold: [criticalThreshold: '0', highThreshold: '0']
                    )
                }
            }
        }
    stage('Deploy') {
      steps {
        echo 'Deploying...'
      }
    }
  }
}
```

</details>
</blockquote>
Whether the step should fail if issues and vulnerabilities are found.
You can pass the following parameters to your `sec1Security` step.

#### `scanFileLocation` (required, default: `${WORKSPACE}`)

Location where scm checkout is done. Default is `${WORKSPACE}` of build job.

Scan will fill if you dont provide this value.

#### `apiCredentialsId` (optional, default: *none*)

Sec1 Api Key Credential ID. As configured in "[2. Configure a Sec1 API Token Credential](#2-configure-a-sec1-api-token-credential)".

### `runSec1SastSecurity` (optional, default: true)
Whether SAST scanner needs to be executed for configured git repository

#### `applyThreshold` (optional, default: `false`)

Whether vulnerability threshold needs to be applied on the build.

#### `threshold` (optional, default: `false`)

Threshold values for each type of vulerability. e.g. configuration:
[criticalThreshold: '0', highThreshold: '10', mediumThreshold: '0', lowThreshold: '0']

If scan reports gives more vulnerabilities than configured threshold for the respective type of vulnerability then error will be shown in console and build status will be modified based on actionOnThresholdBreached value.

#### `actionOnThresholdBreached` (optional, default: `fail`)

The action which needs to be taken on build if vulnerability threshold is breached. Possible values: `fail`, `unstable`, `continue`

## Troubleshooting

To see more information on your steps:

- View the "Console Output" for a specific build.

---

-- Sec1 team
