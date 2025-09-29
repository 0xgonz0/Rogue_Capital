Active Directory Lab Seeding Script
This PowerShell script automates the setup of a complete Active Directory environment for a fictional company, "Rogue Capital." It's designed to quickly build a realistic, pre-populated lab for security research, penetration testing, and systems administration practice.

Features
Fully Automated: Creates a full structure of OUs, users, groups, and GPOs with a single command.

Idempotent: Can be run multiple times without creating duplicate objects or causing errors.

Dry Run Mode: Includes a -DryRun parameter to preview changes before they are made.

Intentionally Vulnerable: The lab is configured with common security misconfigurations for training purposes.

Logging: All actions are recorded to C:\Temp\roguecapital_seed.log for easy review.

Prerequisites
A Windows Server with the Active Directory Domain Services (AD DS) role installed.

The script must be run on a domain-joined machine (preferably a Domain Controller).

The RSAT: Active Directory Domain Services and Group Policy Management tools must be installed.

Usage
Open an elevated PowerShell prompt.

Navigate to the directory where you saved the script.

Execute the script.

Basic Execution:
This will create all the objects defined in the script.

PowerShell

.\Create-RogueCapitalAD.ps1
Dry Run (Preview changes):
This will log all the actions it would take without actually modifying Active Directory.

PowerShell

.\Create-RogueCapitalAD.ps1 -DryRun
Verbose Mode:
This will print the log output to the console in real-time.

PowerShell

.\Create-RogueCapitalAD.ps1 -VerboseLogging
Intended Vulnerabilities 🔓
This script is designed for security labs and deliberately introduces the following misconfigurations:

Excessive Privileges: Executive accounts are made members of the Domain Admins group.

No Account Lockout: The domain password policy is set to never lock out accounts, allowing for unlimited password-guessing attempts.

Weak & Reused Passwords: Users are assigned simple, predictable passwords like Welcome!23.

⚠️ Warning: This script creates a deliberately insecure environment. DO NOT use it in a production network.
