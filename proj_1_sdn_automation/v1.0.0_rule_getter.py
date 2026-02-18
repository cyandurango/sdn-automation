#!/usr/bin/env python3
import subprocess
import json

def fetch_json_from_curl(url, interface='eth1', extra_args=None):
    """
    Executes a curl command to fetch JSON from the given URL over the specified interface,
    then parses and returns the JSON as a Python object (list or dict).
    """
    curl_cmd = ["curl", "--interface", interface, "-s"]
    if extra_args:
        curl_cmd += extra_args
    curl_cmd.append(url)
    
    # Run curl and capture its output
    result = subprocess.run(
        curl_cmd,
        capture_output=True,
        text=True,
        check=True  # raises CalledProcessError on non-zero exit
    )
    
    # Parse the JSON from stdout
    return json.loads(result.stdout)

if __name__ == "__main__":
    controller_ip = "192.168.50.165"
    url = f"http://{controller_ip}:8080/wm/acl/rules/json"

    try:
        # 1) Fetch and store in a Python object
        acl_rules = fetch_json_from_curl(
            url,
            interface="eth1",
            extra_args=["-H", "Content-Type: application/json"]
        )
        
        # 2) Use the same object to pretty-print the entire JSON
        print("Fetched ACL rules (raw JSON):")
        print(json.dumps(acl_rules, indent=2))
        
        # 3) Example: iterate over the list and print each rule's id and protocol
        print("\nRule summary:")
        for rule in acl_rules:
            rid   = rule.get("id")
            proto = rule.get("nw_proto")
            src   = rule.get("nw_src")
            dst   = rule.get("nw_dst")
            print(f"  • ID={rid}, proto={proto}, src={src}, dst={dst}")
            
    except subprocess.CalledProcessError as e:
        print(f"❌ curl failed: {e.stderr}")
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
