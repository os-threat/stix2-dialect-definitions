##############################################################################
# Title: sub.py
# Author: IMG - Incident Mini Group
# Definition Repo: https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc
# Contact Email: 
# Date: 24-07-2023
#
# Description: This file contains Python classes representing the Sub Objects
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

from .vocab import ASSET_TYPE_OV, DETECTION_MTHODS_OV, ENTITY_TYPE_OV, EVENT_TYPE_OV, EXTERNAL_IMPACT_OV, INCIDENT_INVESTIGATION_OV, MONETARY_IMPACT_TYPE_OV, STATE_CHANGE_TYPE_OV, TASK_TYPE_OV
from .enums import ACTIVITY_CONDITION_ENUM, ACTIVITY_TRANSITION_ENUM, EVENT_STATUS_ENUM, INCIDENT_CONFIDENTIALITY_LOSS_ENUM, INCIDENT_DETERMINATION_ENUM, INTEGRITY_ALTERATION_ENUM, PHYSICAL_IMPACT_ENUM, RECOVERABILITY_ENUM, TASK_OUTCOME_ENUM, TIMESTAMP_FIDELITY_ENUMV, TRACEABILITY_ENUM

import logging


############################################################################################
#
# Incident Definitions
#
############################################################################################
# Event sub Object
##################################################################################
class StateChangeObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _properties = OrderedDict([
        ('state_change_type', StringProperty()),
        ('initial_ref', ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version='2.1')),
        ('result_ref', ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version='2.1')),
    ])


###############################################################################
# Imapct sub object
#################################################################################


class EntityCountObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _properties = OrderedDict([
        ('individual', IntegerProperty()),
        ('group', IntegerProperty()),
        ('system', IntegerProperty()),
        ('organization', IntegerProperty()),
        ('class', IntegerProperty()),
        ('unknown', IntegerProperty()),
    ])


###############################################################################
# Incident sub object
#################################################################################

class IncidentScoreObject(_STIXBase21):
    """For more detailed information on this object's properties, see
    `the https://github.com/os-threat/stix-extensions/wiki/2.-Description-of-Incident-Model`__.
    """
    _properties = OrderedDict([
        ('name', StringProperty()),
        ('value', IntegerProperty()),
        ('description', StringProperty()),
    ])
