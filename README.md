# ☁️ Cloud Misconfiguration Auto Scanner

<div align="center">

![Cloud Security](https://img.shields.io/badge/Cloud-Security-blue?style=for-the-badge)
![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)

**A next-generation CSPM-lite tool for automatically detecting misconfigurations in your Azure cloud infrastructure**

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🛡️ Features](#️-features) • [🤝 Contributing](#-contributing)

</div>

---

## 📖 Overview

The **Cloud Misconfiguration Auto Scanner** is an intelligent, automated security tool designed to help organizations identify and remediate security misconfigurations in their Azure cloud environments. Built with modern Python technologies and featuring an intuitive Streamlit-based web interface, this tool provides comprehensive security scanning capabilities with real-time analysis and reporting.

### 🎯 Key Objectives

- **Proactive Security**: Identify security vulnerabilities before they become threats
- **Compliance Assurance**: Ensure adherence to cloud security best practices
- **Automated Scanning**: Reduce manual security auditing overhead
- **Risk Visualization**: Present security findings in an accessible, actionable format
- **Continuous Monitoring**: Enable ongoing security posture assessment

## 🛡️ Features

### 🔍 **Comprehensive Security Scanning**
- **Storage Account Analysis**: Detect public blob access misconfigurations
- **Virtual Machine Auditing**: Identify VMs with unnecessary public IP addresses
- **Network Security Groups**: Flag overly permissive NSG rules (SSH, RDP, wildcard access)
- **Multi-threaded Scanning**: Parallel execution for improved performance

### 📊 **Intelligent Dashboard & Reporting**
- **Interactive Web Interface**: Modern Streamlit-based UI with intuitive navigation
- **Real-time Analytics**: Live dashboard with severity-based metrics and charts
- **Findings Explorer**: Advanced filtering and search capabilities
- **Evidence Collection**: Detailed evidence capture for each finding
- **Export Capabilities**: Generate comprehensive security reports (HTML/PDF - Coming Soon)

### 🗄️ **Data Management & Persistence**
- **SQLite Database**: Persistent storage for scan results and historical data
- **Trend Analysis**: Track security posture improvements over time
- **Raw Data Access**: Database browser for detailed investigation
- **Audit Trail**: Complete history of scans and findings

### 🚀 **Enterprise-Ready Features**
- **Scalable Architecture**: Designed for large-scale Azure environments
- **Service Principal Authentication**: Secure Azure API integration
- **Concurrent Processing**: Multi-threaded scanning for performance
- **Error Handling**: Robust error management and logging
- **Extensible Framework**: Easy to add new security checks

## 🏗️ Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Streamlit UI      │    │   Scanner Engine    │    │   Azure Resources   │
│                     │    │                     │    │                     │
│ • Landing Page      │◄──►│ • Parallel Executor │◄──►│ • Storage Accounts  │
│ • Dashboard         │    │ • Security Checks   │    │ • Virtual Machines  │
│ • Findings Explorer │    │ • Evidence Collector│    │ • Network Sec Groups│
│ • Database Browser  │    │                     │    │ • Public IPs        │
│ • Reports           │    │                     │    │                     │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
           │                           │                           │
           ▼                           ▼                           ▼
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   SQLite Database   │    │   Azure SDK         │    │   Service Principal │
│                     │    │                     │    │                     │
│ • Scan Runs         │    │ • Storage Mgmt      │    │ • Client ID         │
│ • Findings          │    │ • Compute Mgmt      │    │ • Client Secret     │
│ • Evidence          │    │ • Network Mgmt      │    │ • Tenant ID         │
│ • Remediation       │    │ • Identity          │    │ • Subscription ID   │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (Recommended: Python 3.12)
- **Azure Subscription** with appropriate permissions
- **Azure Service Principal** with read access to resources

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/AnirudhDattu/Cloud_Misconfiguration_Auto_Scanner.git
   cd Cloud_Misconfiguration_Auto_Scanner
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Azure credentials**
   ```bash
   # Create .env file from template
   cp .env.example .env
   
   # Edit .env with your Azure credentials
   nano .env
   ```

5. **Run the application**
   ```bash
   # Web Interface
   streamlit run app.py
   
   # CLI Scanner
   python run_scan.py
   ```

### 🔐 Azure Setup

#### Create Service Principal

```bash
# Login to Azure CLI
az login

# Create service principal
az ad sp create-for-rbac --name "cloud-scanner-sp" --role "Reader" --scopes "/subscriptions/{subscription-id}"
```

#### Required Permissions

Your service principal needs the following permissions:
- **Reader** role at subscription or resource group level
- **Storage Account Contributor** (for storage account analysis)
- **Network Contributor** (for NSG analysis)

#### Configuration File (.env)

```bash
# Azure Service Principal Configuration
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret  
AZURE_TENANT_ID=your-tenant-id
AZURE_SUBSCRIPTION_ID=your-subscription-id

# Database Configuration
DB_PATH=./scanner_azure.db
```

## 💻 Usage

### Web Interface

1. **Launch the application**
   ```bash
   streamlit run app.py
   ```

2. **Navigate to `http://localhost:8501`**

3. **Start scanning from the Landing Page**
   - Click "🔥 Run Quick Scan Now"
   - Monitor progress in real-time
   - Review findings in the Dashboard

### Command Line Interface

```bash
# Run full security scan
python run_scan.py

# Run specific checks
python run_nsg_scan.py  # NSG-only scan
```

### 📊 Dashboard Features

#### Landing Page
- Project overview and quick scan initiation
- Real-time scan progress and results summary

#### Dashboard
- Security metrics overview
- Severity-based pie charts
- High-level KPIs and trends

#### Findings Explorer
- Detailed findings table with severity color-coding
- Advanced filtering by severity and service type
- Sortable columns and search functionality
- Evidence and remediation details

#### Database Browser
- Raw database contents inspection
- JSON-formatted findings data
- Audit trail and scan history

## 🔍 Security Checks

### Storage Account Security
- **Rule ID**: `AZ-Storage-PublicBlob-001`
- **Check**: Detects storage accounts with public blob access enabled
- **Severity**: High
- **Impact**: Data exposure risk

### Virtual Machine Security
- **Rule ID**: `AZ-VM-PUBIP-001`
- **Check**: Identifies VMs with public IP addresses
- **Severity**: Medium
- **Impact**: Attack surface expansion

### Network Security Group Analysis
- **Rule ID**: `AZ-NSG-OPEN-001`
- **Check**: Flags NSG rules allowing traffic from 0.0.0.0/0
- **Focus Ports**: 22 (SSH), 3389 (RDP), * (All)
- **Severity**: High
- **Impact**: Unauthorized access risk

## 📁 Project Structure

```
Cloud_Misconfiguration_Auto_Scanner/
├── 📄 README.md                    # Project documentation
├── 📄 CONTRIBUTING.md              # Contribution guidelines
├── 📄 requirements.txt             # Python dependencies
├── 📄 .env.example                 # Environment template
├── 📄 .gitignore                   # Git ignore rules
│
├── 🎯 app.py                       # Main Streamlit application
├── 🔍 run_scan.py                  # CLI scanner entry point
├── 🔍 run_nsg_scan.py             # NSG-specific scanner
│
├── 📊 db/                          # Database layer
│   ├── models.py                   # SQLAlchemy models
│   └── dao.py                      # Data access operations
│
└── 🛡️ scanner/                     # Security scanning modules
    ├── utils.py                    # Configuration utilities
    ├── inventory.py                # Azure resource inventory
    ├── checks_azure.py             # Storage security checks
    ├── check_vms.py                # VM security analysis
    └── check_nsg.py                # Network security checks
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `AZURE_CLIENT_ID` | Service Principal Client ID | Yes | `12345678-1234-1234-1234-123456789012` |
| `AZURE_CLIENT_SECRET` | Service Principal Secret | Yes | `your-secret-value` |
| `AZURE_TENANT_ID` | Azure AD Tenant ID | Yes | `12345678-1234-1234-1234-123456789012` |
| `AZURE_SUBSCRIPTION_ID` | Target Azure Subscription | Yes | `12345678-1234-1234-1234-123456789012` |
| `DB_PATH` | SQLite Database Path | No | `./scanner_azure.db` |

### Database Schema

The application uses SQLite for data persistence with the following schema:

#### Runs Table
- `id`: Primary key
- `started_at`: Scan start timestamp
- `finished_at`: Scan completion timestamp
- `status`: Scan status (running/finished)

#### Findings Table
- `id`: Primary key
- `run_id`: Foreign key to runs table
- `rule_id`: Security rule identifier
- `service`: Azure service type
- `resource_id`: Azure resource identifier
- `title`: Finding description
- `severity`: Risk level (High/Medium/Low)
- `evidence`: JSON evidence data
- `remediation`: JSON remediation steps

## 🚨 Troubleshooting

### Common Issues

#### Authentication Errors
```
Error: Azure creds not found in .env
```
**Solution**: Verify `.env` file contains all required Azure credentials

#### Permission Denied
```
Error: Insufficient permissions to access resource
```
**Solution**: Ensure service principal has "Reader" role on target subscription/resources

#### Module Import Errors
```
ModuleNotFoundError: No module named 'streamlit'
```
**Solution**: Install dependencies with `pip install -r requirements.txt`

#### Database Connection Issues
```
Error: database is locked
```
**Solution**: Ensure only one instance of the application is running

### Debug Mode

Enable debug logging by setting environment variable:
```bash
export PYTHONPATH=$PYTHONPATH:.
export DEBUG=True
```

### Getting Help

1. Check the [Issues](https://github.com/AnirudhDattu/Cloud_Misconfiguration_Auto_Scanner/issues) page
2. Review the [Contributing Guide](CONTRIBUTING.md)
3. Create a new issue with detailed error information

## 🔮 Roadmap

### Upcoming Features
- [ ] **Multi-Cloud Support**: AWS and GCP scanning capabilities
- [ ] **Advanced Reporting**: PDF/HTML export with executive summaries
- [ ] **GenAI Integration**: AI-powered finding explanations and remediation
- [ ] **REST API**: Programmatic access to scanning functionality
- [ ] **Webhook Integration**: Real-time notifications and alerts
- [ ] **Custom Rules Engine**: User-defined security policies
- [ ] **Compliance Frameworks**: CIS, NIST, SOC2 benchmark mapping
- [ ] **Role-Based Access Control**: Multi-user support with permissions

### Version History
- **v1.0.0**: Initial release with core Azure scanning
- **v1.1.0**: Enhanced UI and database persistence
- **v1.2.0**: Multi-threaded scanning and improved performance

## 🤝 Contributing

We welcome contributions from the community! Please see our [Contributing Guide](CONTRIBUTING.md) for detailed information on:

- Development setup
- Code style guidelines  
- Testing procedures
- Pull request process
- Issue reporting

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Azure SDK Team** for comprehensive Azure management libraries
- **Streamlit Community** for the excellent web framework
- **SQLAlchemy Project** for robust database ORM
- **Python Security Community** for cloud security best practices

## 📊 Project Statistics

![GitHub stars](https://img.shields.io/github/stars/AnirudhDattu/Cloud_Misconfiguration_Auto_Scanner?style=social)
![GitHub forks](https://img.shields.io/github/forks/AnirudhDattu/Cloud_Misconfiguration_Auto_Scanner?style=social)
![GitHub issues](https://img.shields.io/github/issues/AnirudhDattu/Cloud_Misconfiguration_Auto_Scanner)
![GitHub pull requests](https://img.shields.io/github/issues-pr/AnirudhDattu/Cloud_Misconfiguration_Auto_Scanner)

---

<div align="center">
  <strong>Made with ❤️ for Cloud Security</strong>
</div>
