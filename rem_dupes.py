import os
import json

in_dir = ["./attack", "./custom", "./extensions"]
in_s_dir =  "./stix"
in_c_file = "/constraints.json"
removed = []
# Get the ATT&CK file
for in_a_dir in in_dir:
    with open(in_a_dir + in_c_file, 'r') as a_input:
        a_constraints = json.load(a_input)
        # Get the Stix file
        with open(in_s_dir + in_c_file, 'r') as s_input:
            s_constraints = json.load(s_input)
            for a_c in a_constraints:
                a_type = a_c["relationship_types"]
                a_source = a_c["source"]
                a_target = a_c["target"]
                # find it in the stix file
                for i, s_c in enumerate(s_constraints):
                    s_source = s_c["source"]
                    s_target = s_c["target"]
                    if s_c["relationship_types"] == a_type:
                        if s_source[0] == a_source[0] and s_target[0] == a_target[0]:
                            del s_constraints[i]
                            removed.append(s_c)
                            break

    with open(in_s_dir + in_c_file, 'w') as outfile:
        json.dump(s_constraints, outfile)

print(removed)