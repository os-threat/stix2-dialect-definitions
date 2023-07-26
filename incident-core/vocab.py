##############################################################################
# Title: vocab.py
# Author: IMG - Incident Mini Group
# Definition Repo: https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc
# Contact Email: 
# Date: 24-07-2023
#
# Description: This file contains named Python dicts, wehre the name is the name of the open-vocab dictionary, and
#                  the vocab value is the key, and the vocab description is the value
#
# This code is licensed under the terms of the BSD 3.
##############################################################################

asset_type_ov = {
    "building-doors": "Doors within buildings or structures.",
    "building-windows": "The exterior or interior windows of buildings or structures.",
    "buildings": "Entire buildings or structures.",
    "computers-mobile": "Mobile devices such as smartphones.",
    "computers-personal": "Workstations or laptops owned by an organization.",
    "computers-server": "Servers owned by an organization.",
    "environment": "Land, environment or the ability of either to support humans or wildlife.",
    "ics-actuator": "Actuator for industrial control systems.",
    "ics-engineering-workstation": "Engineering workstation for industrial control systems.",
    "ics-historian": "Historian for industrial control systems.",
    "ics-hmi": "Human machine interfaces for industrial control systems.",
    "ics-other": "Other Industrial control systems.",
    "ics-plc": "Programmable logic controller for industrial control systems.",
    "ics-safety-system": "Safety system for industrial control systems.",
    "ics-sensor": "Sensor for industrial control systems.",
    "inventory": "Stocks of goods to be sold or consumed.",
    "network-device": "Switches, routers, and wireless communication towers.",
    "private-infrastructure": "Privately owned infrastructure such as roads, plumbing, railways, pipelines and electrical infrastructure.",
    "public-infrastructure": "Publicly owned infrastructure such as roads, plumbing, railways, pipelines and electrical infrastructure.",
    "security-containers": "Safes or other security containers.",
    "vehicles": "Vehicles of various types including cars, trains, and planes."
}
ASSET_TYPE_OV = [x for x  in asset_type_ov]

detection_methods_ov = {
    "automated-tool": "An incident is detected by an automated tool. If this option is used it is generally useful to also include a separate entry for the tool itself.",
    "commercial-solution": "A commercial tool or provider detected this incident. This can be combined with other methods including automated-tool to allow greater fidelity.",
    "external-notification": "An external entity detected this incident and notified the impacted organization.",
    "human-review": "An incident is detected by human threat hunting.",
    "message-from-attacker": "Notification comes from a message provided by the attacker including email, a note left of a message or popup message.",
    "propriety-solution": "An internally developed tool or process detected this incident. This can be combined with other methods including automated-tool to allow greater fidelity.",
    "system-outage": "An incident is detected because a system is no longer available.",
    "user-reporting": "One or more users report an incident."
}
DETECTION_MTHODS_OV = [x for x  in detection_methods_ov]


entity_type_ov = {
    "computers-mobile": "Mobile devices such as smartphones.",
    "computers-personal": "Workstations or laptops owned by an organization.",
    "computers-server": "Servers owned by an organization.",
    "customer": "A customer or client. This can be an individual or organization",
    "customer-individual": "A customer or client that represents an individual.",
    "customer-organization": "A customer or client that represents a business or other organization.",
    "domain-controller": "A windows domain controller.",
    "employee": "An employee of an organization.",
    "group": "An informal collection of people, without formal governance, such as a distributed hacker group.",
    "ics-actuator": "Actuator for industrial control systems.",
    "ics-engineering-workstation": "Engineering workstation for industrial control systems.",
    "ics-historian": "Historian for industrial control systems",
    "ics-hmi": "Human machine interfaces for industrial control systems.",
    "ics-other": "Other Industrial control systems.",
    "ics-plc": "Programmable logic controller for industrial control systems.",
    "ics-safety-system": "Safety system for industrial control systems.",
    "ics-sensor": "Sensor for industrial control systems.",
    "individual": "A single person.",
    "network-device": "Switches, routers, and wireless communication towers.",
    "organization": "A formal organization of people, with governance, such as a company or country.",
    "system": "A computer system, such as a SIEM.",
    "vehicles": "Vehicles of various types including cars, trains, and planes."
}
ENTITY_TYPE_OV = [x for x  in entity_type_ov]

event_type_ov = {
    "aggregation-information-phishing-schemes": "Collecting data obtained through phishing attacks on web pages, email accounts, etc…",
    "benign": "The event was neither dangerous nor malicious and was not suspected to be malicious or dangerous.",
    "blocked": "The event was suspected to be malicious and was blocked.",
    "brute-force-attempt": "Unsuccessful login attempt by using sequential credentials for gaining access to the system.",
    "c&c-server-hosting": "Web page disseminating one or various types of malware.",
    "compromised-system": "Attackers obtained control of a compromised system.",
    "confirmed": "The event was confirmed to be tied to an incident and response is underway.",
    "connection-malware-port": "System attempting to gain access to a port normally linked to a specific type of malware.",
    "connection-malware-system": "System attempting to gain access to an IP address or URL normally linked to a specific type of malware, e.g. C&C or a distribution page for components linked to a specific botnet.",
    "content-forbidden-by-law": "Distribution or sharing of illegal content such as child pornography, racism, xenophobia, etc",
    "control-system-bypass": "Unauthorized access to a system or component by bypassing an access control system in place.",
    "copyrighted-content": "Distribution or sharing of content protected by copyright and related rights.",
    "data-exfiltration": "Unauthorized access to and sharing of a specific set of information.",
    "deferred": "The event is deferred due to resource constraints, information types or external reasons.",
    "deletion-information": "Unauthorized deleting of a specific set of information.",
    "denial-of-service": "The event or incident resulted in a loss of availability for a service or system. Incidents of this type SHOULD have an availability impact, but organizations may choose to not share the details of these impacts.",
    "destruction": "The event or incident destroyed data or systems. Incidents of this SHOULD have an integrity impact, but organizations may choose to not share the details of these impacts.",
    "dictionary-attack-attempt": "Unsuccessful login attempt by using system access credentials previously loaded into a dictionary.",
    "discarded": "The event was discarded due to resource constraints, information types or external reasons.",
    "disruption-data-transmission": "Logical and physical activities aimed at causing damage to information or at preventing its transmission among systems.",
    "dissemination-malware-email": "Malware attached to a message or email message containing link to malicious URL.",
    "dissemination-phishing-emails": "Mass emailing aimed at collecting data for phishing purposes with regard to the victims.",
    "dns-cache-poisoning": "DNS cache poisoning - also known as DNS spoofing, is a type of cyber attack in which an attacker corrupts a DNS resolver’s cache by injecting false DNS records, causing the resolver to records controlled by the attacker.",
    "dns-local-resolver-hijacking": "Consumer Premise Equipment (CPE), such as home routers, often provide DNS recursion on the local network. If the CPE device is compromised, the attacker can change the recursive resolver behavior; for example, by changing responses.",
    "dns-spoofing-registered": "In a context where a domain name is expected (such as the From header in mail or a URL in a web page or message body), supplying a domain name not controlled by the attacker and that is in fact controlled by or registered to a legitimate registrant.",
    "dns-rebinding": "DNS rebinding - a type of attack where a malicious website directs a client to a local network address, allowing the attacker to bypass the same-origin policy and gain access to the victim’s local resources.",
    "dns-server-compromise": "Attacker gains administrative privileges on an open recursive DNS server, authoritative DNS server, organizational recursive DNS server, or ISP-operated recursive DNS server.",
    "dns-spoofing-unregistered": "In a context where a domain name is expected (such as the From header in mail or a URL in a web page or message body), supplying a domain name not controlled by the attacker and that is not controlled by or registered to a legitimate registrant.",
    "dns-stub-resolver-hijacking": "The attacker compromises the Operating System of a computer or a phone with malicious code that intercepts and responds to DNS queries with rogue or malicious responses.",
    "dns-zone-transfer": "Transfer of a specific DNS zone.",
    "domain-name-compromise": "The wrongfully taking control of a domain name from the rightful name holder. Compromised domains can be used for different kinds of malicious activity like sending spam or phishing, for distributing malware or as botnet command and control.",
    "duplicate": "This event is a duplicate of another event. A relationship should be created between this event and the event it duplicates.",
    "email-flooding": "Sending an unusually large quantity of email messages.",
    "equipment-loss": "A loss of control of physical equipment that is not known to be theft.",
    "equipment-theft": "Theft of equipment. In general this should be paired with equipment-loss.",
    "exploit": "Successful use of a tool exploiting a specific vulnerability of the system.",
    "exploit-attempt": "Unsuccessful use of a tool exploiting a specific vulnerability of the system.",
    "exploit-framework-exhausting-resources": "Various sources using specially designed software to affect the normal functioning of a specific service, by exploiting a vulnerability.",
    "exploit-tool-exhausting-resources": "One single source using specially designed software to affect the normal functioning of a specific service, by exploiting a vulnerability.",
    "failed": "The event failed its suspected goal.",
    "file-inclusion": "Inclusion of files into a system under attack with the use of file inclusion techniques.",
    "file-inclusion-attempt": "Unsuccessful attempt to include files in the system under attack by using file inclusion techniques.",
    "hosting-malware-webpage": "Web page disseminating one or various types of malware.",
    "hosting-phishing-sites": "Hosting web sites for phishing purposes.",
    "illegitimate-use-name": "Using the name of an institution without permission to do so.",
    "illegitimate-use-resources": "Use of institutional resources for purposes other than those intended.",
    "infected-by-known-malware": "The presence of any of the types of malware was detected in a system.",
    "insufficient-data": "Not enough data is available to assess this event.",
    "known-malware": "This incident involves a known type of malware. Events and incidents SHOULD be related to a Malware object, but organizations may choose not to share the details on this malware.",
    "lame-delegations": "Lame delegations occur as a result of expired name server domains allowing attackers to take control of the domain resolution by re-registering this expired name server domain.",
    "major": "The incident is classified as major based on the internal criteria within the organization or due to external reporting requirements.",
    "modification-information": "Unauthorized changes to a specific set of information.",
    "misconfiguration": "A false positive where this event was triggered by a misconfiguration.",
    "natural": "The event was due to natural causes such as an earthquake or hurricane.",
    "negotiation": "Negotiation of a deal or payment amount.",
    "network-scanning": "Scanning a network aimed at identifying systems which are active in the same network.",
    "no-apt": "It is not believed that this incident involved an advanced persistent threat.",
    "packet-flood": "Mass mailing of requests (network packets, emails, etc…​) from various sources to a specific service, aimed at affecting its normal functioning.",
    "password-cracking-attempt": "Attempt to acquire access credentials by breaking the protective cryptographic keys.",
    "policy-violation": "The event or incident was a violation of organizational or regulatory policy.",
    "ransomware": "This incident involved malware that encrypted data with a demand that a ransom is paid to regain access to it.",
    "ransomware-payment": "The event or incident associated with actually paying a ransom.",
    "refuted": "The event was previously suspected to have achieved a goal, but this has since been refuted.",
    "scan-probe": "Event was triggered based on scanning activity",
    "silently-discarded": "The event was silently discarded due to resource constraints, information types or external reasons.",
    "supply-chain-customer": "This incident used a vendor further up in the supply chain where the target was a customer.",
    "supply-chain-vendor": "This incident targeted a system or product that is supplied to others to enable further attacks.",
    "spam": "Sending an email message that was unsolicited or unwanted by the recipient.",
    "sql-injection": "Manipulation or reading of information contained in a database by using the SQL injection technique.",
    "sql-injection-attempt": "Unsuccessful attempt to manipulate or read the information of a database by using the SQL injection technique.",
    "successful": "The event is believed to have succeeded in its goal.",
    "system-probe": "Single system scan searching for open ports or services using these ports for responding.",
    "theft-access-credentials": "Unauthorized access to a system or component by using stolen access credentials.",
    "unattributed": "This event or incident has not been attributed. It is unclear if it is tied to a specific advanced persistent threat group.",
    "unauthorized-access-information": "Unauthorized access to a set of information. Incidents of this SHOULD have a confidentiality impact, but organizations may choose to not share the details of these impacts.",
    "unauthorized-access-system": "Unauthorized access to a system or component.",
    "unauthorized-equipment": "Usage of unauthorized devices as part of the incident",
    "unauthorized-release": "The unauthorized release of information.Incidents of this SHOULD have a confidentiality impact, but organizations may choose to not share the details of these impacts.",
    "unauthorized-use": "The usage of information that falls outside of official purposes",
    "undetermined": "Field aimed at the classification of unprocessed events, which have remained undetermined from the beginning.",
    "unintentional": "The event was due to unintentional activity.",
    "unknown-apt": "This incident is believed to involve an advanced persistent threat, but the specific APT is unknown.",
    "unspecified": "Other unlisted events.",
    "vandalism": "Logical and physical activities which - although they are not aimed at causing damage to information or at preventing its transmission among systems - have this effect.",
    "wiretapping": "Logical or physical interception of communications.",
    "worm-spreading": "System infected by a worm trying to infect other systems.",
    "xss": "Attacks performed with the use of cross-site scripting techniques.",
    "xss-attempt": "Unsuccessful attempts to perform attacks by using cross-site scripting techniques."
}
EVENT_TYPE_OV = [x for x  in event_type_ov]

external_impact_ov = {
    "economic": "This incident is expected to have national or international economic impacts.",
    "emergency-services": "This incident impacts emergency services.",
    "foreign-relations": "This incident impacts international politics.",
    "national-security": "This incident impacts the national security of one or more nations.",
    "public-confidence": "This incident impacts the confidence in public or private institutions.",
    "public-health": "This incident impacts the public health of one or more nations.",
    "public-safety": "This incident impacts the public safety of individuals in one or more nations."
}
EXTERNAL_IMPACT_OV = [x for x  in external_impact_ov]

incident_investigation_ov = {
    "closed": "All defender work on this incident has been concluded. In some cases, blue teams may make child Incidents of a closed Incident. In these cases, it is appropriate to mark an initial Incident as closed if the related child incidents that track this work are still open.",
    "new": "A new incident that has not begun the formal workflow on the defender’s network.",
    "open": "An open incident that is currently being worked."

}
INCIDENT_INVESTIGATION_OV = [x for x  in incident_investigation_ov]



information_type_ov = {
    "classified-material": "Data classified based on relevant government authorities.",
    "communication": "Communication records including emails, chats and instant messages.",
    "credentials-admin": "Administrative credential data.",
    "credentials-user": "User credential data.",
    "financial": "Financial records including purchasing activity and planned activities.",
    "legal": "Legal records that are not yet public including contracts under negotiation and documents protected under legal privilege.",
    "payment": "Payment information.",
    "phi": "Protected Health Information.",
    "pii": "Personally Identifiable Information.",
    "proprietary": "Proprietary information e.g., intellectual property.",
    "system": "Information necessary to keep a system operational. The destruction or encryption of this data can cause availability impacts."
}
INFORMATION_TYPE_OV= [x for x  in information_type_ov]



monetary_impact_type_ov = {
    "asset-and-fraud": "Losses incurred due to loss of assets or fraud.",
    "brand-damage": "Losses incurred due to reputational or brand damage.",
    "business-disruption": "Losses incurred due to business disruptions.",
    "competitive-advantage": "Losses incurred due to theft of intellectual property, techniques or other capabilities that grant an advantage in the field.",
    "legal-and-regulatory": "Losses incurred due to legal or regulatory actions in response to the incident.",
    "operating-costs": "Losses incurred due to additional operating costs that have been incurred due to the incident.",
    "ransom-demand": "The demanded amount of ransom to be paid. When this is selected the demand amount should be listed as the max_amount and the min_amount should be 0.",
    "ransom-payment": "An actual payment of a ransom.",
    "response-and-recovery": "Losses incurred due to response and recovery efforts for the incident.",
    "uncategorized": "Losses incurred that have not been categorized yet."

}
MONETARY_IMPACT_TYPE_OV = [x for x  in monetary_impact_type_ov]



state_change_type_ov = {
    "caused": "This task or event is the primary cause of the resulting object.",
    "contributed-to": "This task or event is a contributing factor to the result occurring.",
    "input": "This task or event took in a group as an input for automated or playbook activities. If this is selected initial_ref MUST be populated.",
    "mitigated": "This task or event lessened the severity of the initial object.",
    "output": "This task or event produced a group as an output as part of automated or playbook activities.If this is selected result_ref MUST be populated.",
    "resolved": "This task or event resolved the initial object.",

}
STATE_CHANGE_TYPE_OV = [x for x  in state_change_type_ov]



task_type_ov = {
    "administrative": "Perform an administrative action such as the introduction or change of a policy.",
    "attribution": "Perform an administrative action such as the introduction or change of a policy.",
    "containment": "The containment phase of incident response",
    "declared": "When this was officially declared an incident.",
    "detected": "When the incident was detected.",
    "eradication": "The eradication phase of incident response.",
    "escalated": "When the incident was escalated to a major incident.",
    "exercised-control": "Attempted to use a security control that was already in place within the environment.",
    "external-intelligence": "Used external intelligence information.",
    "external-outreach": "Reaching out to an external organization to gain support or information.",
    "external-support": "Acquire support from an external organization.",
    "implemented-control": "Implemented a security control within the environment.",
    "investigation": "Performed an investigation into an event or incident.",
    "negotiation": "Negotiation of a deal or payment amount.",
    "playbook-execution": "Executing a step in an automated playbook. If the playbook is stored outside of STIX both the playbook and step stored in separate external-reference objects. If playbook steps feed each other information that is designed to be passed as STIX it SHOULD be referenced as a grouping as either the initial_ref or result_ref of a state-change.",
    "playbook-step-execution": "Executing a step in an automated playbook. If the playbook is stored outside of STIX both the playbook and step stored in separate external-reference objects. If playbook steps feed each other information that is designed to be passed as STIX it SHOULD be referenced as a grouping as either the initial_ref or result_ref of a state-change.",
    "ransom-payment": "An actual payment of a ransom.",
    "recovery": "The recovery phase of incident response.",
    "reported": "When the incident was reported externally.",
    "routine-updates": "Performed a routine update in the environment including patching.",
    "victim-notification": "Notified victims, potentially impacted individuals or organizations about the incident."

}
TASK_TYPE_OV = [x for x  in task_type_ov]

