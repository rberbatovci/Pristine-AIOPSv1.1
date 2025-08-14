##### ACTIVELY DEVELOPING ####

Pristine AIOps – Network Fault and Performance Monitoring

Pristine AIOps is a modern, modular platform for real-time network fault and performance monitoring. It ingests and processes data from multiple sources—including Syslogs, SNMP Traps, NetFlow, and Model-Driven Telemetry—via Kafka pipelines to generate actionable insights and correlated signals.

🚀 Features
✅ Real-time processing of Syslogs, SNMP Traps, NetFlow, and Telemetry

🏷️ Tag extraction from logs and traps using customizable regex rules

📈 Signal correlation based on severity, mnemonics, OIDs, and tag matches

🔍 Advanced filtering, querying, and statistical dashboards

🧠 Extensible and future-ready architecture

📦 Docker-Based Deployment
This project uses Docker Compose for production-ready deployment with all components pre-packaged and public containers available through the dhrc Docker registry.

To get started:

	git clone https://github.com/rberbatovci/Pristine-AIOPSv1.1.git
	cd Pristine-AIOPSv1.1
	docker-compose -f docker-compose.prod.yml up --build

⚙️ Device Configuration
To start monitoring your infrastructure, follow these steps for each network device:

Register your device:
Add your device's IP address and hostname to the platform.

Configure your devices to send data to Kafka producers:

Syslogs → Point syslog output to the designated Kafka producer.

SNMP Traps → Configure SNMP agent to send traps to the designated trap receiver.

NetFlow → Export flow data to the NetFlow collector endpoint.

Telemetry (gNMI, etc.) → Push telemetry streams to the telemetry Kafka producer.

Ensure connectivity: All data sources should be routed to the correct service endpoints as defined in your deployment configuration.

🏷️ Tag Extraction & Signal Correlation
Syslogs
Use custom regex rules to extract tags from syslog messages.

Apply these regexes to syslog mnemonics for tagging.

Correlate logs into signals using severity, tag matches, and stateful correlation rules.

SNMP Traps
Define and tag OIDs.

Match tagged OIDs against snmpTrapOid.0 for correlation.

Correlate traps into signals similarly using rule sets and matching criteria.

📊 Query & Visualize
Query syslogs, traps, and telemetry data via the web interface.

View statistics and tag-based aggregations.

Explore signals and understand fault propagation.

🧪 In Development
We're currently working on an Incidents Dashboard, which will:

Perform advanced signal correlation across multiple data sources.

Classify incidents using ML-assisted logic.

Automatically notify teams through your preferred channels (email, Slack, etc.).

📚 Documentation
	Full documentation on creating regex rules, tagging strategies, and configuring correlation logic will be provided soon.

📬 Feedback & Contributions
	Have a feature request, bug report, or idea? Open an issue or contribute directly via a pull request. Community involvement is welcome!

Let me know if you want this broken into multiple sections (e.g., docs, guides) or want a badge section added.
