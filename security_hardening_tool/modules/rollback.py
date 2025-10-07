
import json
import os
from datetime import datetime

ROLLBACK_DIR = "rollback"

def store_previous_state(parameter, value):
    """
    Stores the previous state of a parameter before hardening.
    """
    if not os.path.exists(ROLLBACK_DIR):
        os.makedirs(ROLLBACK_DIR)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    rollback_file = os.path.join(ROLLBACK_DIR, f"rollback_{timestamp}.json")
    
    data = {}
    if os.path.exists(rollback_file):
        with open(rollback_file, "r") as f:
            data = json.load(f)
            
    data[parameter] = value
    
    with open(rollback_file, "w") as f:
        json.dump(data, f, indent=4)

def rollback_changes(timestamp):
    """
    Rolls back changes to a previous state.
    """
    rollback_file = os.path.join(ROLLBACK_DIR, f"rollback_{timestamp}.json")
    if not os.path.exists(rollback_file):
        print(f"Rollback file not found: {rollback_file}")
        return

    with open(rollback_file, "r") as f:
        rollback_data = json.load(f)

    for parameter, value in rollback_data.items():
        # This is a placeholder for the actual rollback logic
        print(f"Rolling back '{parameter}' to '{value}'")
        # set_value(parameter, value) # This would be the actual call
