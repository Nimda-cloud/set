# NIMDA Security System - Comprehensive Monitoring

A comprehensive security monitoring system with Tkinter GUI, featuring real-time network monitoring, port scanning, anomaly detection, and AI-powered analysis with Ukrainian/English language support.

## 🚀 Features

### Core Security Monitoring
- **Real-time Network Monitoring**: Track active connections, detect suspicious traffic
- **Port Scanning**: Monitor open ports, identify vulnerable services
- **Anomaly Detection**: Detect system anomalies with detailed analysis
- **Threat Assessment**: AI-powered threat analysis and recommendations
- **Security Logging**: Comprehensive event logging and reporting

### 🔊 Advanced Sound Alert System
- **Multi-level Threat Sounds**: Different sounds for each threat level (LOW to EMERGENCY)
- **macOS System Integration**: Uses native macOS sounds (Tink, Pop, Sosumi, Basso, Funk)
- **Intelligent Alert Intervals**: Adaptive timing based on threat severity
- **Emergency Siren Mode**: Continuous alerts for critical situations
- **Sound Pattern Recognition**: Unique audio patterns for different threat types

### 📊 Threat Level Analysis
- **5-Level Threat Classification**: LOW, MEDIUM, HIGH, CRITICAL, EMERGENCY
- **Automated Response System**: Automatic actions based on threat level
- **Real-time Threat Scoring**: Dynamic threat assessment with context analysis
- **Historical Threat Tracking**: Complete threat history and trend analysis
- **Smart Context Analysis**: IP analysis, malware signatures, privilege escalation detection

### AI-Powered Analysis
- **Multi-language AI Support**: Ukrainian and English responses
- **Deep Analysis**: Detailed analysis of ports, addresses, and anomalies
- **Security Recommendations**: AI-generated security recommendations
- **Emergency Analysis**: Rapid threat assessment and response
- **Comprehensive Reports**: AI-generated security reports

### Advanced Analysis Features
- **Deep Port Analysis**: Detailed analysis of individual ports with risk assessment
- **Deep Address Analysis**: Comprehensive analysis of network addresses
- **Bulk Analysis**: Quick analysis of all ports and addresses
- **Anomaly Analysis**: Detailed root cause analysis and mitigation steps
- **Language Switching**: Toggle between Ukrainian and English interfaces

## 🛠️ Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd set
```

2. **Install dependencies**:
```bash
pip3 install -r requirements.txt
```

3. **Install Ollama** (for AI features):
```bash
# macOS
brew install ollama

# Or download from https://ollama.ai
```

4. **Start Ollama and download a model**:
```bash
ollama serve
ollama pull llama2
```

## 🚀 Usage

### Quick Start
```bash
# Start the GUI application
python3 nimda_tkinter.py

# Or use the startup script
./start_nimda_tkinter.sh
```

### GUI Interface

#### Dashboard Tab
- Real-time system metrics (CPU, Memory, Network)
- Threat level indicators
- Quick status overview

#### Network Tab
- Active network connections
- Remote address analysis
- Connection blocking capabilities
- Deep address analysis

#### Ports Tab
- Open port monitoring
- Service identification
- Port risk assessment
- Deep port analysis

#### Anomalies Tab
- Real-time anomaly detection
- Detailed anomaly analysis
- Root cause analysis
- Mitigation recommendations

#### AI Analysis Tab
- **Multi-language AI queries** (Ukrainian/English)
- Security threat analysis
- AI recommendations
- Emergency analysis
- Language switching button

#### Logs Tab
- Security event logging
- Export capabilities
- Historical analysis

#### Emergency Tab
- System lockdown
- Network isolation
- Process termination
- Emergency backup

## 🔧 Configuration

### Language Settings
- Click the "🌐 Language" button in the Anomalies tab to switch UI language
- Click the "🌐 Switch AI Language" button in the AI Analysis tab to switch AI response language
- AI will respond in the selected language for all queries

### Security Monitoring
- Automatic baseline establishment
- Configurable update intervals
- Customizable threat thresholds

## 📊 Analysis Features

### Deep Port Analysis
- Service identification
- Risk level assessment
- Security concerns
- Mitigation recommendations
- Port scanning results

### Deep Address Analysis
- Geolocation information
- Reputation checking
- Connection details
- Security assessment
- Recommendations

### Anomaly Analysis
- Root cause analysis
- Impact assessment
- Mitigation steps
- Prevention measures
- Related threats
- System health status

## 🧪 Testing

Run the test scripts to verify functionality:

```bash
# Test deep analysis
python3 test_deep_analysis.py

# Test anomaly analysis
python3 test_anomaly_analysis.py

# Test AI language functionality
python3 test_ai_language.py

# Test GUI components
python3 test_gui.py
```

## 🔍 Troubleshooting

### Common Issues

1. **Network scan errors**: Normal on some systems, shows test data
2. **Ollama connection issues**: Ensure Ollama is running and accessible
3. **Permission errors**: Run with appropriate permissions for system monitoring

### Debug Mode
```bash
# Enable debug logging
export NIMDA_DEBUG=1
python3 nimda_tkinter.py
```

## 📝 Logging

The system provides comprehensive logging:
- Security events
- AI interactions
- System anomalies
- Network activities
- Error tracking

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Check the troubleshooting section
- Review the logs for error details
- Test individual components
- Ensure all dependencies are installed

## 🔄 Updates

The system automatically:
- Updates security baselines
- Refreshes network data
- Detects new anomalies
- Maintains AI context

---

**NIMDA Security System** - Comprehensive security monitoring with AI-powered analysis and multi-language support.
