import json
import re
import subprocess
import sys


def extract_onion_hosts_from_file(path):
    with open(path, 'r') as f:
        data = f.readlines()
    hosts = []
    for i in data:
        res = strip_onion_host(i)
        if len(res):
            hosts.append(res)
    return hosts


def strip_onion_host(any_address):
    p = re.compile("[a-zA-Z0-9]+.onion")
    result = p.search(any_address)
    if result is None:
        return ''
    return result.group(0)


def check_single_host(hostname):
    res = subprocess.run(["proxychains4", "nmap", "-sV", "-p", "80", hostname], stdout=subprocess.PIPE).stdout.decode(
        'utf-8')
    res = [i for i in res.split("\n") if i != '']
    return res


def check_web_server(data_list):
    res = {"total": 0, "failed": 0}
    for host in data_list.keys():
        res["total"] += 1
        record = data_list[host]
        tmp = record[5].split(" ")
        tmp = [i for i in tmp if i != ""]
        if "80/tcp" == tmp[0] and "open" == tmp[1]:
            server_info = "_".join(tmp[2:])
            if server_info in res:
                res[server_info] += 1
            else:
                res[server_info] = 1
        else:
            res["failed"] += 1
    res["success"] = res["total"] - res["failed"]
    return res


if __name__ == '__main__':
    path = sys.argv[1]
    out_path = sys.argv[2]
    hosts = extract_onion_hosts_from_file(path)
    res = {}
    for h in hosts:
        res[h] = check_single_host(h)
        with open(out_path, "w") as f:
            res_str = json.dumps(res)
            f.write(res_str)
