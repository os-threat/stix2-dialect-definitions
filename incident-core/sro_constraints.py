##############################################################################
# Title: sro-constraints.py
# Author: IMG - Incident Mini Group
# Definition Repo: https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc
# Contact Email: denis@cloudaccelerator.co
# Date: 24-07-2023
#
# Description: This file contains at of dicts containing, name of the relation-type
#         and source_ref and target_ref object constratins 
#
# This code is licensed under the terms of the BSD 3.
##############################################################################

import json
import pathlib

from stix2.v21.base import _DomainObject, _STIXBase21, _RelationshipObject, _Observable
from stix2.v21.sdo import (
    AttackPattern, Campaign, CourseOfAction, CustomObject, Grouping, Identity, 
    Incident, Indicator, Infrastructure, IntrusionSet, Location, Malware, 
    MalwareAnalysis, Note, ObservedData, Opinion, Report, ThreatActor, 
    Tool, Vulnerability,
)
from stix2.v21.observables import (
    URL, AlternateDataStream, ArchiveExt, Artifact, AutonomousSystem,
    CustomObservable, Directory, DomainName, EmailAddress, EmailMessage,
    EmailMIMEComponent, File, HTTPRequestExt, ICMPExt, IPv4Address,
    IPv6Address, MACAddress, Mutex, NetworkTraffic, NTFSExt, PDFExt, Process,
    RasterImageExt, SocketExt, Software, TCPExt, UNIXAccountExt, UserAccount,
    WindowsPEBinaryExt, WindowsPEOptionalHeaderType, WindowsPESection,
    WindowsProcessExt, WindowsRegistryKey, WindowsRegistryValueType,
    WindowsServiceExt, X509Certificate, X509V3ExtensionsType,
)
from .sdo import  Event, Task, Evidence, Impact

#######################################################################
#
# There is currently no directory or file when one can encode and enforce:
#   1. A registry of valid "relationship_types", and
#   2. A registry of their constraints, acceptable object types for source_ref and target_ref
# Enabling relationship constraints seems a worthy goal
#
#######################################################################

constraints = [
    {"source":[Incident], "relationship_types": "led-to", "target":[Incident], "description":"One incident led to another."},
    {"source":[Incident], "relationship_types": "impacts", "target":[Identity, Infrastructure], "description":"An incident has an impact on the victim or specific infrastructure."},
    {"source":[Incident], "relationship_types": "attributed-to", "target":[IntrusionSet, ThreatActor], "description":"The incident has been attributed to the intrusion set or threat actor."},
    {"source":[Incident], "relationship_types": "targets", "target":[Identity, Infrastructure], "description":"An incident was targeted at the victim or specific infrastructure."},
    {"source":[Incident], "relationship_types": "located-at", "target":[Location], "description":"The incident occurred at a specific location or locations."},
    {"source":[Campaign], "relationship_types": "associated-with", "target":[Incident], "description":"The incident in question is part of the campaign that is associated with"},
    {"source":[Identity], "relationship_types": "contact-for", "target":[Incident], "description":"An identity should be considered a point of contact for an incident. This can be used to supplement the created_by_ref in cases where external authorship would prevent using it for this purpose."},
    {"source":[Indicator], "relationship_types": "", "target":[Incident], "description":"An indicator was responsible for detecting the incident."},
    {"source":[Event], "relationship_types": "led-to", "target":[Event], "description":"One event led to another. For example a dropper running allowed a ransomware tool to be downloaded and run."},
    {"source":[Event], "relationship_types": "impacts", "target":[Infrastructure, _Observable], "description":"An event has an impact on specific infrastructure."},
    {"source":[Event], "relationship_types": "located-at", "target":[Location], "description":"The event occurred at a specific location or locations."},
    {"source":[Event], "relationship_types": "observed", "target":[_Observable], "description":"STIX cyber-observables were observed as part of this event, but no information on when they are observed is being shared. If this can be shared a Sighting it should be instead of using this method."},
    {"source":[Indicator], "relationship_types": "based-on", "target":[Event], "description":"An indicator is based on an event."},
    {"source":[Malware], "relationship_types": "performed", "target":[Event], "description":"Malware performed a specific event."},
    {"source":[Tool], "relationship_types": "performed", "target":[Event], "description":"A tool performed a specific event."},
    {"source":[Task], "relationship_types": "uses", "target":[CourseOfAction], "description":"An task uses a particular course of action."},
    {"source":[Task], "relationship_types": "blocks", "target":[Event], "description":"A task was performed to block a potential event."},
    {"source":[Task], "relationship_types": "causes", "target":[Event], "description":"A task was performed that caused an event, usually due to an error."},
    {"source":[Task], "relationship_types": "detects", "target":[Event], "description":"A task was used to detect an event."},
    {"source":[Task], "relationship_types": "creates", "target":[Indicator], "description":"A task was performed that created an indicator."},
    {"source":[Task], "relationship_types": "impacts", "target":[Infrastructure, _Observable], "description":"A task has an impact on specific infrastructure."},
    {"source":[Task], "relationship_types": "located-at", "target":[Location], "description":"The task occurred at a specific location or locations."},
    {"source":[Task], "relationship_types": "errored-to", "target":[Task], "description":"A task follows this one because of an error / if statement in a playbook."},
    {"source":[Task], "relationship_types": "followed-by", "target":[Task], "description":"A task follows this one in the normal chain of execution."},
    {"source":[Identity], "relationship_types": "assigned", "target":[Task], "description":"An identity has been assigned the task"},
    {"source":[Identity], "relationship_types": "contact-for", "target":[Task], "description":"An identity is a point of contact for this task."},
    {"source":[Identity], "relationship_types": "participated-in", "target":[Task], "description":"An identity participated in a specific task, but as not the primary performer"},
    {"source":[Identity], "relationship_types": "performed", "target":[Task], "description":"An identity performed a specific task."},
    {"source":[Tool], "relationship_types": "performed", "target":[Task], "description":"A tool performed a specific task."}
]
