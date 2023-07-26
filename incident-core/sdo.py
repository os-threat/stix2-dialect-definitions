##############################################################################
# Title: sdo.py
# Author: IMG - Incident Mini Group
# Definition Repo: https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc
# Contact Email: 
# Date: 24-07-2023
#
# Description: This file contains Python classes representing the Domain Objects
#
# This code is licensed under the terms of the BSD 3.
##############################################################################\

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

from .vocab import ASSET_TYPE_OV, DETECTION_MTHODS_OV, ENTITY_TYPE_OV, EVENT_TYPE_OV, EXTERNAL_IMPACT_OV, INCIDENT_INVESTIGATION_OV, MONETARY_IMPACT_TYPE_OV, STATE_CHANGE_TYPE_OV, TASK_TYPE_OV
from .enums import ACTIVITY_CONDITION_ENUM, ACTIVITY_TRANSITION_ENUM, EVENT_STATUS_ENUM, INCIDENT_CONFIDENTIALITY_LOSS_ENUM, INCIDENT_DETERMINATION_ENUM, INTEGRITY_ALTERATION_ENUM, PHYSICAL_IMPACT_ENUM, RECOVERABILITY_ENUM, TASK_OUTCOME_ENUM, TIMESTAMP_FIDELITY_ENUMV, TRACEABILITY_ENUM
from .sub import StateChangeObject, EntityCountObject, IncidentScoreObject
from .ext import ImpactCoreExt, Availability, Confidentiality, External, Integrity, Monetary, Physical, Traceability, EventCoreExt, IncidentCoreExt, TaskCoreExt, EvidenceCoreExt
import logging



class Event(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'event'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('status', EnumProperty(EVENT_STATUS_ENUM)),
        ('changed_objects', ListProperty(EmbeddedObjectProperty(type=StateChangeObject))),
        ('description', StringProperty()),
        ('detection_methods', ListProperty(StringProperty)),
        ('detection_rule', StringProperty()),
        ('detection_system', StringProperty()),
        ('end_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end_time_fidelity', EnumProperty(TIMESTAMP_FIDELITY_ENUMV)),
        ('event_seq', IntegerProperty()),
        ('event_types', ListProperty(OpenVocabProperty(EVENT_TYPE_OV))),
        ('goal', StringProperty()),
        ('name', StringProperty()),
        ('sighting_refs', ListProperty(ReferenceProperty(valid_types=["SCO", "SRO", "SDO"], spec_version='2.1'))),
        ('start_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start_time_fidelity', EnumProperty(TIMESTAMP_FIDELITY_ENUMV)),
        ('subevents', ListProperty(ReferenceProperty(valid_types='event', spec_version='2.1'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    
class Task(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'task'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('changed_objects', ListProperty(EmbeddedObjectProperty(type=StateChangeObject))),
        ('task_type', OpenVocabProperty(TASK_TYPE_OV)),
        ('step_type', StringProperty()),
        ('outcome', StringProperty()),
        ('description', StringProperty()),
        ('end_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end_time_fidelity', EnumProperty(TIMESTAMP_FIDELITY_ENUMV)),
        ('error', StringProperty()),
        ('impacted_entity_counts', EmbeddedObjectProperty(type=EntityCountObject)),
        ('name', StringProperty(required=True)),
        ('priority', IntegerProperty(min=0)),
        ('start_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start_time_fidelity', EnumProperty(TIMESTAMP_FIDELITY_ENUMV)),
        ('owner', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('on_completion', ReferenceProperty(valid_types='task')),
        ('on_failure', ReferenceProperty(valid_types='task')),
        ('on_success', ReferenceProperty(valid_types='task')),
        ('next_steps', ListProperty(ReferenceProperty(valid_types='task'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])

    
class Evidence(_DomainObject):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'evidence'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('evidence_type', StringProperty()),
        ('source', StringProperty()),
        ('object_refs', ListProperty(ReferenceProperty(valid_types=["SCO", "SRO", "SDO"], spec_version='2.1'))),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])


class Impact(_DomainObject):
    """For more detailed information on this object's properties, see
        `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _type = 'impact'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('impact_category', StringProperty()),
        ('criticality', IntegerProperty()),
        ('description', StringProperty()),
        ('end_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('end_time_fidelity', EnumProperty(TIMESTAMP_FIDELITY_ENUMV)),
        ('impacted_entity_counts', EmbeddedObjectProperty(type=EntityCountObject)),
        ('impacted_refs', ListProperty(ReferenceProperty(valid_types=["SCO", "SRO", "SDO"], spec_version='2.1'))),
        ('recoverability', EnumProperty(RECOVERABILITY_ENUM)),
        ('start_time', TimestampProperty(default=lambda: NOW, precision='millisecond', precision_constraint='min')),
        ('start_time_fidelity', EnumProperty(TIMESTAMP_FIDELITY_ENUMV)),
        ('superseded_by_ref', ReferenceProperty(valid_types='impact', spec_version='2.1')),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])
