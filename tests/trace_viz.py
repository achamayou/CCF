import sys
import json
import rich

# TODO
# Calculate alignment based on max nodes, view, index, commit index
# Only highlight individual state changes
     
LEADERSHIP_STATUS = {
    "None": ":beginner:",
    "Leader": ":crown:",
    "Follower": ":guard:",
    "Candidate": ":person_raising_hand:"
}

FUNCTIONS = {
    "add_configuration": "Cfg",
    "replicate": "Rpl",
    "send_append_entries": "SAe",
    "recv_append_entries": "RAe",
    "execute_append_entries_sync": "EAe",
    "send_append_entries_response": "SAeR",
    "recv_append_entries_response": "RAeR",
    "send_request_vote": "SRv",
    "recv_request_vote": "RRv",
    "recv_request_vote_response": "RRvR",
    "recv_propose_request_vote": "RPRv",
    "become_candidate": "BCan",
    "become_leader": "BLea",
    "become_follower": "BFol",
    "commit": "Cmt",
    None: ""
}
    
def render_state(state, func, old_state):
    if state is None:
        return " "
    ls = LEADERSHIP_STATUS[state["leadership_state"]]
    nid = state["node_id"]
    v = state["current_view"]
    i = state["last_idx"]
    c = state["commit_idx"]
    f = FUNCTIONS[func]
    opc = "bold bright_white on red" if func else "normal"
    sc = "white on red" if func and (old_state != state) else "grey93"
    return f"[{opc}]{nid:>2}{ls}{f:<4} [/{opc}][{sc}]{v:>2}v {i:>3}i {c:>3}c[/{sc}]"

    
def table(lines):
    entries = [json.loads(line) for line in lines]
    nodes = []
    for entry in entries:
        node_id = entry["msg"]["state"]["node_id"]
        if node_id not in nodes:
            nodes.append(node_id)
    node_to_state = {}
    rows = []
    for entry in entries:
        node_id = entry["msg"]["state"]["node_id"]
        old_state = node_to_state.get(node_id)
        node_to_state[node_id] = entry["msg"]["state"]
        states = [(node_to_state.get(node),
                   entry["msg"]["function"] if node == node_id else None,
                   old_state if node == node_id else None)  for node in nodes]
        rows.append("     ".join(render_state(*state) for state in states))
    return rows
    
if __name__ == "__main__":
    with open(sys.argv[1]) as tf:
        for line in table(tf.readlines()):
            rich.print(line)