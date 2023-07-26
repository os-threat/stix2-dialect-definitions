##############################################################################
# Title: enums.py
# Author: IMG - Incident Mini Group
# Definition https://github.com/dod-cyber-crime-center/cti-stix-common-objects/blob/incident_rework/extension-definition-specifications/incident-core/Incident%20Extension%20Suite.adoc
# Contact Email: denis@cloudaccelerator.co
# Date: 24-07-2023
#
# Description: This file contains named-dicts, representing the value and description
#               of the Enum
#
# This code is licensed under the terms of the BSD 3.
##############################################################################


activity_condition_enum = {
    "optional": "The following event or task does not depend on the current one.",
    "test": "The following event or task depends on the current one",
    "required": "The following event or task depends on the current one.",
    "unknown": "It is unknown if the following event or task depends on the current on"
}
ACTIVITY_CONDITION_ENUM = [x for x  in activity_condition_enum]



activity_transition_enum = {
    "completion": "The following task executed when this one completed regardless of success or failure.",
    "failure": "The following task executed when this one failed.",
    "success": "The following task executed upon success.",
    "unknown": "It is unknown what conditions cause the following task to execute only that it followed the current on"
}
ACTIVITY_TRANSITION_ENUM = [x for x  in activity_transition_enum]



event_status_enum = {
    "ongoing": "The event is still occurring.",
    "occurred": "The event took and is no longer ongoing.",
    "not-occurred": "The event did not take place, but it was previously expected to.",
    "pending": "The event has not yet been started or observed, but it is projected or otherwise planned. Pending activity may never occur as various factors can cause it to be blocked or not attempted. As such any time or sequence values for pending activities should be treated as an estimation or projection that is subject to chan",
    "undetermined": "The status of the event has not been determined or is not shareable."
}
EVENT_STATUS_ENUM = [x for x  in event_status_enum ]


incident_confidentiality_loss_enum = {
    "confirmed-loss": "Information has been exfiltrated and is now available to the attacker, but it is unknown if it has been misused.",
    "contained": "Information’s confidentiality was compromised, but the spill was within an environment that allowed it to be effectively contained.For example: a sensitive data spill occurred within a controlled network allowing it to be resolved before information exited the organization.",
    "exploited-loss": "Information has been exfiltrated and has been actively misused by the attacker.",
    "none": "This information type was not compromised based on the investigation that was performed. This option should be used to affirmatively supply this information when necessary.",
    "suspected-loss": "It is suspected but not confirmed that the attacker may have gained access to this information."
}
INCIDENT_CONFIDENTIALITY_LOSS_ENUM = [x for x  in incident_confidentiality_loss_enum]

incident_determination_enum = {
    "blocked": "The incident had no or minimal impact due to pre-emptive measures including rate limiting or spam filters.",
    "confirmed": "An incident has been determined to have caused at least some harm or violated a policy.",
    "failed-attempt": "The incident had no or minimal impact but not due to any affirmative defense for example a password guesser failed but was also not rate limited.",
    "false-positive": "An incident was determined to have been triggered by a false alert and no action including automatically performed automated actions were needed to remediate the issue. This should not be used when an incident was flagged correctly, but is of no importance. For findings of that nature low-value should be used.",
    "suspected": "An incident is suspected, but not yet confirmed."

}
INCIDENT_DETERMINATION_ENUM = [x for x  in incident_determination_enum]

integrity_alteration_enum = {
    "potential-destruction": "Information may have been destroyed within the system.",
    "potential-modification": "Information may have been modified within the system.",
    "partial-destruction": "Some data of this type has been destroyed, but sufficient data remains to allow partial functionality.",
    "partial-modification": "Some data in the system has been modified, but the remaining data is of an acceptable level of integrity for operations to continue.",
    "full-destruction": "Sufficient data of this type was destroyed to render the system inoperable until recovery can be completed.",
    "full-modification": "Sufficient data of this type was modified to render the system inoperable until recovery can be completed.",
    "none": "There is no evidence of destruction or modification of this data type in the system."
}
INTEGRITY_ALTERATION_ENUM = [x for x  in integrity_alteration_enum]

physical_impact_enum = {
    "damaged-functional": "The property, asset or system was damaged but still remains functional and repair may be possible.",
    "damaged-nonfunctional": "The property, asset or system was damaged and does not remain functional, but repair may be possible.",
    "destruction": "The property, asset or system was destroyed, cannot be repaired and no longer functions. In some cases destroyed assets can be rebuilt, but doing so involves a similar amount of effort as the original construction.",
    "none": "No damage or destruction has occurred.",
    "unknown": "The degree of damage has not been determined yet."

}
PHYSICAL_IMPACT_ENUM = [x for x  in physical_impact_enum]

recoverability_enum = {
    "extended": "Time to recovery is unpredictable; additional resources and outside help are necessary.",
    "not-applicable": "No recovery is necessary.",
    "not-recoverable": "Recovery from the incident is not possible.",
    "regular": "Time to recovery is predictable with existing resources.",
    "supplemented": "Time to recovery is predictable with additional resources."

}
RECOVERABILITY_ENUM = [x for x  in recoverability_enum]

task_outcome_enum = {
    "cancelled": "The task was planned or started, but later cancelled or discarded.",
    "failed": "The task has been completed, but failed.",
    "ongoing": "The task is still taking place.",
    "pending": "The task has not yet been started, but is currently planned.",
    "successful": "The task was completed successfully.",
    "unknown": "The status of this task is currently unknown."
}
TASK_OUTCOME_ENUM = [x for x  in task_outcome_enum]

timestamp_fidelity_enum = {
    "day": "The associated timestamp should be considered to represent a time within the one day period starting with the provided timestamp.Hours and minutes should be understood to establish the timezone for this activity.",
    "hour": "The associated timestamp should be considered to represent a time within the one hour period starting with the provided timestamp.",
    "minute": "The associated timestamp should be considered to represent a time within the one minute period starting with the provided timestamp.",
    "month": "The associated timestamp should be considered to represent a time within the one month period starting with the provided timestamp. Hours and minutes should be understood to establish the timezone for the activity. The day should always be listed as the first or the last day of the previous month if in a timezone that is offset before UTC.",
    "second": "The associated timestamp should be considered to represent a time within the one second period starting with the provided timestamp.",
    "year": "The associated timestamp should be considered to represent a time within the one year period starting with the provided timestamp. Hours and minutes should be understood to establish the timezone for the activity.",
}
TIMESTAMP_FIDELITY_ENUMV = [x for x  in timestamp_fidelity_enum]

traceability_enum = {
    "accountability-lost": "Traces used to retrieve accountability are lost or do not exist.",
    "partial-accountability": "Traces are present, but insufficient to have provable accountability.",
    "provable-accountability": "Accountability can be ensured from the traces that are present",

}
TRACEABILITY_ENUM = [x for x  in traceability_enum]
