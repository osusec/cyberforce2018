#!/usr/bin/env python3

from datetime import datetime

log_path = "httpd_after_1_2_3_5_6_8_9_10_11_13_14_15.log"

def log(msg):
    print("[*] {}".format(msg))


def error(msg, do_exit=False):
    print("[!] {}".format(msg))
    if do_exit:
        exit(1)


def get_log():
    log("loading in log: {}".format(log_path))
    lines = []
    with open(log_path, "r") as f:
        for l in f.readlines():
            data = l.split(" ")
            lines.append({
                "ts": datetime.strptime(" ".join(data[:2]), "%Y-%m-%d %H:%M:%S"),
                "src_ip": data[2],
                "user": data[3],
                "dst_ip": data[4],
                "dst_port": int(data[5]),
                "method": data[6],
                "uri": data[7],
                "ua": data[8],
                "response_code": int(data[9].strip())
            })
    log("finished loading in log")
    return lines


def anomaly1(log_data):
    selection = {}
    for l in log_data:
        if l["response_code"] == 401:
            if l["user"] in selection:
                selection[l["user"]].append(l)
            else:
                selection[l["user"]] = [l]
            
            log("added hit for {}".format(l["user"]))

    users = []
    for k, v in selection.items():
        for x in range(len(v)-1):
            delta = v[x+1]["ts"] - v[x]["ts"]
            m, _ = divmod(delta.total_seconds(), 60)
            if m <= 10:
                users.append(k)

    return users


def anomaly2(log_data):
    freq = {}
    for l in log_data:
        if l["uri"] == "/login.php" and l["response_code"] == 200:
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1
    
    sorted_list = sorted(freq.items(), key=lambda kv: kv[1])
    print(sorted_list[0])
    print(sorted_list[-1])


def anomaly3(log_data):
    freq = {}
    for l in log_data:
        if "/financials.dll" in l["uri"]:
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1

    freq = sorted(freq.items(), key=lambda kv: kv[1])
    
    print(freq[-1])


def anomaly5(log_data):
    freq = {}
    for l in log_data:
        if "/docs.cfm" in l["uri"]:
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1

    freq = sorted(freq.items(), key=lambda kv: kv[1])
    
    print(freq[-1])


def anomaly6(log_data):
    users = {}
    bad = []
    for l in log_data:
        if "/docs.cfm" in l["uri"]:
            if l["user"] not in users:
                users[l["user"]] = [l["ua"]]
            else:
                if l["ua"] not in users[l["user"]]:
                    bad.append(l["user"])

    print(bad)


# doesn't work, idk why
# Lori.Roberts
def anomaly8(log_data):
    freq = {}
    for l in log_data:
        if "sales" in l["uri"]:
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1
    
    print(freq)


def anomaly9(log_data):
    freq = {}
    for l in log_data:
        if l["method"] != "GET" and l["method"] != "POST":
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1
    
    print(freq)


def anomaly10(log_data):
    freq = {}
    for l in log_data:
        if l["response_code"] == 204 and l["uri"] == "/search.do":
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1
    
    print(freq)


# need to re-run this with less data
def anomaly11(log_data):
    # re-run after doing more early ones
    freq = {}
    for l in log_data:
        BOD = l["ts"].replace(hour=8, minute=30, second=0, microsecond=0)
        EOD = l["ts"].replace(hour=17, minute=30, second=0, microsecond=0)
        if EOD < l["ts"] or BOD > l["ts"] or l["ts"].weekday() >= 5:
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1
    
    print(freq)


def anomaly12(log_data):
    freq = {}
    for l in log_data:
        if "PC" not in l["ua"]:
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1
    
    print(freq)


def anomaly13(log_data):
    freq = {}
    for l in log_data:
        if l["dst_ip"] != "10.1.0.15" and (l["dst_port"] == 80 or l["dst_port"] == 443):
            if l["user"] in freq:
                freq[l["user"]] += 1
            else:
                freq[l["user"]] = 1
    
    print(freq)


def anomaly14(log_data):
    # search query at the same time every day
    # uri: /search.do
    data = {}
    for l in log_data:
        if l["uri"] == "/search.do":
            if l["user"] in data:
                data[l["user"]].append(l["ts"])
            else:
                data[l["user"]] = [l["ts"]]

    #sorted_list = sorted(data.items(), key=lambda kv: len(kv[1]))

    for k, v in data.items():
        print(k)
        for x in v:
            print(x)
        print()


def anomaly15(log_data):
    remotes = {}
    misconfigured = []
    for x in log_data:
        if x["dst_port"] == 443 or x["dst_port"] == 80:
            if x["dst_ip"] not in remotes:
                remotes[x["dst_ip"]] = [x["dst_port"]]
            else:
                if x["dst_port"] not in remotes[x["dst_ip"]]:
                    if x["dst_ip"] not in misconfigured:
                        misconfigured.append(x["dst_ip"])

    users = {} 
    for x in log_data:
        if x["dst_ip"] in misconfigured and x["dst_port"] == 80:
            if x["user"] not in users:
                users[x["user"]] = 1
            else:
                users[x["user"]] += 1
    
    print(users)


def main():
    log_data = get_log()
    anomaly6(log_data)


if __name__ == "__main__":
    main()