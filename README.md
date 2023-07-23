# Stix2-Dialect-Definitions

The OASIS Stix2 Python Library is a vey powerful capability, yet limited to the Stix 2.1 objects defined in its system. OS-Threat has extended the Stix 2 library to support
- the use of TypeDB as a DataStore, making it simple to add, retrieve and delete Stix2-compatible objects in the knowledge Graph
- developing definitions comptaible with the OASIS Stix2 library, for new dialects to extend library capabilities to: 
    - Incident-Core, (standardised incident management and reporting)
    - OS-Threat,  (custom objects for importing threat feeds)
    - ATT&CK , (Mitre ATT&CK Reference Library Objects)
now, with 
    - CACAO, (Automated Playbooks to Hunt, Configure, Triage etc.)
    - Kestrel, (Specialised, Powerful Hunting Capabilities)
    - CVE, (List of all the Software Vulnerabilities) 
    - Control Compass (Test, Detect, and Mitigate Resources for ATT&CK Techniques) 
    - CSAF/SBOM, (Software Bill-of-Materials, Library Vulnerability Registry)
coming in the future.

## Stix2 Dialects - A Group of Related Definitions
The repo definitions are broken into individual dialects, that are compatible with the OASIS Stix 2 object modelling approach. Most of the definitions can be easily imported into OASIS Stix2 using an extension to current machinery. However, support for the ATT&CK objects are more complicated as the value of their typename property is insufficient to categorise the object type or class, and sometimes a value constraint on different object property is also required (e.g. "subtechnique" : True)

A dialect is a selcted grouping of objects and relationship for a common purpose. A dialect definitions includes Python classes, for properties, sdo, sco, sro, and extensions, combined with CSV/JSON data definitions for contraints, vocabulry, enums, and files for docs, icons and the spec (official extension defintion)

Additionally, a docs direcgtory can contain markdown documents on definitions, and a specs directoy can contain the official exxtension: adoc, json schema, and examples directories. 

## Dialect Definition - 9 Classes of Definitions
For each dialect, the directories are:
- docs: markdown objects to describe the objects, and datae in this repo
- enums: named-key-value JSON file for each enum dictionary, where the filename is the enum name, the key is the word and a description of the word is in the value
- ext: An ext.py file containing extension classes
- props: A props.py file containing Python classes for additional property classes
- sco: A sco.py file cotnaining Python classes for additonal observable object classes
- sdo: A sdo.py file containing Python classes for additional domain objects 
- sro: A sro.py file containing Python classes for additional sro objects, unusual but ATT&CK requires one
- sro-registry: A JSON List of New relation_types 
- sro-cont=straints: A JSON List of Dicts for additonal Relation connection constraints, each Dict containing the name of the relation_type, the source object and the target object constraints
- vocab: named-key-value JSON file for each open-vocab dictionary, where the filename is the diconary name, the key is the word and a description of the word is in the value

## Initial Dataset - For Testing
The aim is to put forward at least three completely filled dialect definitions, so that OASIS Stix2 authors can see the value of building an extension to import these definitions, which would produce a radical extension to the value of the current OASIS Stix2 library. It will have far greater utility, and can become the common platform for all OASIS protocols/dialects, if it can integrate these library-compatible definitions into its own registries. Note that some of the sub-directories may be empty, so the aim is to search a list of directory's to import a specific type of file/files for each directory, if it exists.

In order to test this concept we will launch the test Definitions with 3 dialects:
1. Incident-Core-Ext: As developed by the US DoD and OS Threat collaboration
2. OS-Threat-Feeds: Custom objects developed by OS-Threat for handling Intel Feeds
3. Mitre ATT&CK: The latest version of the Mitre ATT&CK knowledge base dialect

If OASIS Stix2 library builds an extension to import these definitons, then OS-Threat will expand the list considerably, eventually across every OASIS protocol, and may other common dialects

