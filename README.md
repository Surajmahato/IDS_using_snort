# Network Threat Detection System

## Project Overview
This repository includes a comprehensive framework for testing and enhancing network threat detection mechanisms, focusing on:

- Simulating various types of network traffic, including normal and malicious activities.
- Detecting threats such as SQL Injection, Cross-Site Scripting (XSS), and Command Injection.
- Evaluating the performance of custom and optimized Snort rulesets.

## Project Structure

### Files and Scripts
1. **pcap_generator.py**
   - Generates PCAP files simulating different types of network traffic:
     - Normal traffic
     - XSS attacks
     - SQL Injection
     - Command Injection

2. **snort_test_framework.py**
   - Provides a framework for analyzing PCAP files and detecting attacks based on predefined rules.
   - Features include:
     - Detection rate calculation
     - False positive analysis
     - Enhanced detection strategies for SQL Injection, XSS, and Command Injection.

3. **snort_test_workflow.py**
   - Implements a workflow to:
     - Load PCAP files and Snort rules.
     - Compare custom and optimized rulesets.
     - Save results as CSV and generate visual reports.

## Key Features

- **Traffic Simulation**: Generate realistic network traffic for testing.
- **Attack Detection**: Identify malicious activities using advanced detection strategies.
- **Ruleset Comparison**: Evaluate the effectiveness of custom vs. optimized Snort rules.
- **Performance Reporting**: Generate detailed reports and visualizations.

## Installation

### Prerequisites
- Python 3.8 or higher
- Required Python libraries (listed in `requirements.txt`)
- Snort installed for testing rulesets

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/Surajmahato/IDS_using_snort.git
   cd IDS_using_snort
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txta
   ```

## Usage

### Generating Traffic
Run the `pcap_generator.py` script to create PCAP files with simulated traffic:
```bash
python pcap_generator.py
```

### Testing with Snort
Use the `snort_test_workflow.py` to evaluate the performance of Snort rulesets:
```bash
python snort_test_workflow.py
```

### Viewing Results
- CSV reports are saved in the `results` directory.
- Visualizations are generated as PNG images for easier analysis.

## Configuration
- Modify the `pcap_generator.py` script to adjust the number and types of packets.
- Update Snort rules in `rules/custom_rules.rules` and `rules/optimized_rules.rules` for testing.

## Contributing
We welcome contributions to improve the detection framework. To contribute:
1. Fork the repository.
2. Create a new branch for your changes:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes and push to your fork:
   ```bash
   git commit -m "Description of changes"
   git push origin feature-name
   ```
4. Submit a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contact
For any inquiries or support, contact:
- **Name**: [Your Name]
- **Email**: [Your Email]
- **GitHub**: [Your GitHub Profile Link]
