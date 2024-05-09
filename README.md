# Stix2-Dialect-Definitions

The OASIS Stix2 Python Library has a vey powerful capability, to validate, create, store, send, retrieve Domain, Observable and Relationship Objects yet limited to the Stix 2.1 objects defined in its system. OS-Threat has extended the Stix 2 library to support
- the use of TypeDB as a DataStore, making it simple to add, retrieve and delete Stix2-compatible objects in the knowledge Graph
- developing vocab, enum and SRO constraint definitions comptaible with the OASIS Stix2 library,: 
    - stix -> Stix v2.1
    - extensions -> Incident-Core and other extensions
    - osthreat -> OS-Threat,  (custom objects for importing threat feeds)
    - attack -> ATT&CK , (Mitre ATT&CK Reference Library Objects)
now, 

In the future we plan to extend to 
    - IoB (Indicators of Behaviour)
    - CACAO, (Automated Playbooks to Hunt, Configure, Triage etc.)
    - Kestrel, (Specialised, Powerful Hunting Capabilities)
    - CVE, (List of all the Software Vulnerabilities) 
    - Control Compass (Test, Detect, and Mitigate Resources for ATT&CK Techniques) 
    - CSAF/SBOM, (Software Bill-of-Materials, Library Vulnerability Registry)
coming in the future.

## Stix2 Dialects - A Group of Related Definitions
The repo definitions are broken into individual directories, that are compatible with the OASIS Stix 2 object modelling approach. 

A dialect is a selcted grouping of objects and relationship for a common purpose. A dialect definitions includes data definitions for SRO contraints and vocabulry, enums dictionaries.
