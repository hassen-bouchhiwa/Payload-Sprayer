# Payload Sprayer - Automated Payload Injection for Burp Suite

Payload Sprayer is a Burp Suite extension designed to enhance vulnerability detection by automating payload injection across multiple HTTP parameters simultaneously. This tool provides a streamlined approach to identifying vulnerabilities by executing injections over several parameters in one go, enabling faster and more comprehensive assessments.

With its built-in interface, Payload Sprayer displays injection results through a range of metrics, making it easier to spot anomalies and vulnerabilities. Additionally, it automates the generation and execution of commands for SQLMap, Dalfox, Commix, and Tplmap, allowing testers to initiate targeted checks using these specialized tools directly within the Burp environment

## Installation

1. **Install Jython**:
   - Download Jython from the [Jython website](https://www.jython.org/download).
   - In Burp Suite, go to `Extensions > Options > Python Environment` and specify the Jython JAR path.

2. **Run the Install Script**:
   - Execute `install.sh` to install necessary dependencies:
     ```bash
     sudo ./install.sh
     ```

3. **Add the Extension in Burp**:
   - In Burp Suite, go to `Extensions > Add` and add the Payload Sprayer Python file.

4. **Set Up Configurations**:
   - Open the `Configuration` tab in Payload Sprayer within Burp Suite to set paths for any external tools and add the OpenAI API key if AI-assisted features are enabled.

## Basic Usage

1. **Prepare Requests**
   - **Navigate and Capture**: Navigate you application and use Burp Suite Proxy to browse and capture HTTP requests for testing.
   - **Send to Tool**: Right-click on desired requests and forward them to the tool. The tool automatically extracts injection points based on your selection (parameters, headers, or endpoints).

2. **Select Parameters for Testing**
   - Identify and choose specific parameters from the requests that you wish to target in testing.

3. **Injection Testing Workflow**
   - **Select Injection Mode**: Choose between single payload, wordlist-based, or custom injection modes for testing across the selected parameters.
   - **Execute Injections**: Start the injection process across chosen parameters.
   - **Review Results**: Analyze injection outcomes, with multiple metrics displayed to help spot vulnerabilities or anomalies.

4. **Automated Scanner Workflow**
   - **Configure Scanners**: Choose from available scanner tools such as SQLMap, Dalfox, Commix, or Tplmap, and specify scanner options.
   - **Generate and Launch Commands**: Allow the tool to automatically generate the scanner commands and execute them.
   - **Inspect Scanner Results**: Review the scanner outputs for detected vulnerabilities and additional insights.

For more detailed usage instructions, refer to the [Payload Sprayer Documentation](link-to-documentation).
