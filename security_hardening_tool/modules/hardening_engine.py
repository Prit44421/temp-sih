
import json
import subprocess
import os
from datetime import datetime
from .rollback import store_previous_state

def load_rules(os_name):
    """
    Loads hardening rules from the JSON file for the specified OS.
    """
    rules_path = os.path.join("config", "rules.json")
    with open(rules_path, "r") as f:
        all_rules = json.load(f)
    return all_rules.get(os_name, [])

def apply_hardening(os_name, level):
    """
    Applies hardening rules to the system.
    """
    rules = load_rules(os_name)
    report = []
    for rule in rules:
        if rule['level'] == level:
            parameter = rule['parameter']
            expected_value = rule['value']
            
            # Store previous state for rollback
            previous_value = get_current_value(parameter)
            store_previous_state(parameter, previous_value)

            # Apply the rule
            success, current_value = set_value(parameter, expected_value)
            
            report.append({
                "parameter": parameter,
                "previous_value": previous_value,
                "current_value": current_value,
                "status": "successful" if success else "unsuccessful"
            })
    return report

def get_current_value(parameter):
    """
    Gets the current value of a security parameter.
    (This is a placeholder and needs to be implemented for each OS)
    """
    # For demonstration, we'll just return a dummy value
    return "dummy_previous_value"

def set_value(parameter, value):
    """
    Sets the value of a security parameter.
    (This is a placeholder and needs to be implemented for each OS)
    """
    # For demonstration, we'll simulate a successful change
    return True, value

