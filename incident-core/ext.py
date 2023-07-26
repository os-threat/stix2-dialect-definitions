##############################################################################
# Title: ext.py
# Author: IMG - Incident Mini Group
# Definition Repo: https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc
# Contact Email: 
# Date: 24-07-2023
#
# Description: This file contains Python classes representing Extensions
#
# This code is licensed under the terms of the BSD 3.
##############################################################################

import json
import pathlib
from collections import OrderedDict

from stix2.exceptions import (
    PropertyPresenceError, )
from stix2.properties import (
    BooleanProperty, ExtensionsProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty, FloatProperty,
    TimestampProperty, TypeProperty, EmbeddedObjectProperty, ReferenceProperty, EnumProperty
)
from stix2.utils import NOW, _get_dict
from stix2.markings import _MarkingsMixin
from stix2.markings.utils import check_tlp_marking
from stix2.v21.base import _DomainObject, _STIXBase21, _RelationshipObject, _Extension
from stix2.v21.common import (
    ExternalReference, GranularMarking, KillChainPhase,
    MarkingProperty, TLPMarking, StatementMarking,
)
from stix2.v21.vocab import (
    ATTACK_MOTIVATION, ATTACK_RESOURCE_LEVEL, IMPLEMENTATION_LANGUAGE, MALWARE_CAPABILITIES, MALWARE_TYPE,
    PROCESSOR_ARCHITECTURE, TOOL_TYPE, IDENTITY_CLASS, INDUSTRY_SECTOR,
)

from .vocab import ASSET_TYPE_OV, DETECTION_MTHODS_OV, ENTITY_TYPE_OV, EVENT_TYPE_OV, EXTERNAL_IMPACT_OV, INFORMATION_TYPE_OV, INCIDENT_INVESTIGATION_OV, MONETARY_IMPACT_TYPE_OV, STATE_CHANGE_TYPE_OV, TASK_TYPE_OV
from .enums import ACTIVITY_CONDITION_ENUM, ACTIVITY_TRANSITION_ENUM, EVENT_STATUS_ENUM, INCIDENT_CONFIDENTIALITY_LOSS_ENUM, INCIDENT_DETERMINATION_ENUM, INTEGRITY_ALTERATION_ENUM, PHYSICAL_IMPACT_ENUM, RECOVERABILITY_ENUM, TASK_OUTCOME_ENUM, TIMESTAMP_FIDELITY_ENUMV, TRACEABILITY_ENUM
from .sub import StateChangeObject, EntityCountObject, IncidentScoreObject

import logging




class ImpactCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--7cc33dd6-f6a1-489b-98ea-522d351d71b9'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class Availability(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'availability'
    _properties = OrderedDict([
        ('availability_impact', IntegerProperty()),
    ])


class Confidentiality(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'confidentiality'
    _properties = OrderedDict([
        ('information_type', StringProperty()),
        ('loss_type', EnumProperty(INCIDENT_CONFIDENTIALITY_LOSS_ENUM)),
        ('record_count', IntegerProperty()),
        ('record_size', IntegerProperty()),
    ])

class External(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'external'
    _properties = OrderedDict([
        ('impact_type', OpenVocabProperty(EXTERNAL_IMPACT_OV)),
    ])


class Integrity(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'integrity'
    _properties = OrderedDict([
        ('alteration', EnumProperty(INTEGRITY_ALTERATION_ENUM)),
        ('information_type', OpenVocabProperty(INFORMATION_TYPE_OV)),
        ('record_count', IntegerProperty()),
        ('record_size', IntegerProperty()),
    ])


class Monetary(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'monetary'
    _properties = OrderedDict([
        ('variety', OpenVocabProperty(MONETARY_IMPACT_TYPE_OV)),
        ('conversion_rate', FloatProperty()),
        ('conversion_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('currency', StringProperty()),
        ('currency_actual', StringProperty()),
        ('max_amount', FloatProperty()),
        ('min_amount', FloatProperty()),
    ])


class Physical(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'physical'
    _properties = OrderedDict([
        ('impact_type', EnumProperty(PHYSICAL_IMPACT_ENUM)),
        ('asset_type', OpenVocabProperty(ASSET_TYPE_OV)),
    ])



class Traceability(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc`__.
    """

    _type = 'traceability'
    _properties = OrderedDict([
        ('traceability_impact', EnumProperty(TRACEABILITY_ENUM)),
    ])




class EventCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--4ca6de00-5b0d-45ef-a1dc-ea7279ea910e'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])


class IncidentCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--ef765651-680c-498d-9894-99799f2fa126'
    _properties = OrderedDict([
        ('determination', EnumProperty(INCIDENT_DETERMINATION_ENUM)),
        ('extension_type', StringProperty(fixed='property-extension')),
        ('investigation_status', OpenVocabProperty(INCIDENT_INVESTIGATION_OV)),
        ('criticality', IntegerProperty(min=0)),
        ('blocked', BooleanProperty()),
        ('malicious', BooleanProperty()),
        ('impacted_entity_counts', EmbeddedObjectProperty(type=EntityCountObject)),
        ('recoverability',EnumProperty(RECOVERABILITY_ENUM)),
        ('scores', EmbeddedObjectProperty(type=IncidentScoreObject)),
        ('incident_types', ListProperty(StringProperty)),
        ('task_refs', ListProperty(ReferenceProperty(valid_types='task'))),
        ('event_refs', ListProperty(ReferenceProperty(valid_types='event'))),
        ('impact_refs', ListProperty(ReferenceProperty(valid_types='impact'))),
        ('notes_refs', ListProperty(ReferenceProperty(valid_types='notes'))),
        ('evidence_refs', ListProperty(ReferenceProperty(valid_types='evidence'))),
    ])


class TaskCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--2074a052-8be4-4932-849e-f5e7798e0030'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])



class EvidenceCoreExt(_Extension):
    """For more detailed information on this object's properties, see
    `the  https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """

    _type = 'extension-definition--7ff5b5a5-a342-417e-9c0d-339561d9d78a'
    _properties = OrderedDict([
        ('extension_type', StringProperty(fixed='new-sdo')),
    ])

