# encoding: utf-8
import json, time, requests, calendar, re, base64, hashlib
from pathlib import Path

# ---------------------------
# AOB entrypoints
# ---------------------------
def validate_input(helper, definition):
    ot = (definition.parameters.get("object_type") or "").lower()
    if ot not in ("users", "hosts", "dns", "certs", "groups", "hbac", "rbac"):
        raise ValueError("object_type must be users|hosts|dns|certs|groups|hbac|rbac")

def use_single_instance_mode():
    return False

# ---------------------------
# Utilities
# ---------------------------
def _resolve_verify(helper):
    # Prefer CA file path if provided; else bool verify_ssl
    ca = (helper.get_global_setting("ca_cert_path") or "").strip()
    if ca:
        p = Path(ca)
        if p.exists():
            return str(p)
        helper.log_warning("ca_cert_path not found: {}".format(ca))
    return str(helper.get_global_setting("verify_ssl") or "").lower() == "true"

def _emit_records(helper, ew, base_url, object_type, results):
    now = int(time.time())
    for rec in results:
        ew.write_event(helper.new_event(
            sourcetype="idm:json",
            time=now,
            data=json.dumps({
                "idm_server": base_url,
                "object_type": object_type,
                "record": rec
            })
        ))

def _first(v):
    if isinstance(v, list) and v:
        return v[0]
    return v

def _gtime_to_epoch(s):
    # Parse LDAP GeneralizedTime like 20251103204231Z -> epoch (UTC)
    try:
        if isinstance(s, list):
            s = s[0]
        if isinstance(s, (int, float)):
            return int(s)
        if isinstance(s, str) and s.endswith("Z"):
            t = time.strptime(s, "%Y%m%d%H%M%SZ")
            return int(calendar.timegm(t))
    except Exception:
        return None
    return None

def _dnsname(v):
    v = _first(v)
    if isinstance(v, dict) and "__dns_name__" in v:
        return v["__dns_name__"]
    return v

def _emit_dns_record_events(helper, ew, base_url, zone, recs):
    now = int(time.time())
    for rec in recs:
        name = _dnsname(rec.get("idnsname"))
        if not name:
            continue
        fqdn = name if name.endswith(".") else f"{name}.{zone}"
        rr_map, rr_types = {}, []
        for k, v in rec.items():
            if k in ("idnsname", "objectclass", "dn"):
                continue
            rr_map[k] = v
            rr_types.append(k)

        ew.write_event(helper.new_event(
            sourcetype="idm:json",
            time=now,
            data=json.dumps({
                "idm_server": base_url,
                "object_type": "dns_record",
                "zone": zone,
                "name": name,
                "fqdn": fqdn,
                "rr_types": rr_types,
                "rrdata": rr_map,
                "record": rec
            })
        ))

# ---------------------------
# Main collector
# ---------------------------
def collect_events(helper, ew):
    # Global settings
    base_url = (helper.get_global_setting("base_url") or "").strip()
    if not base_url:
        helper.log_error("Missing base_url in Global settings")
        return
    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    verify = _resolve_verify(helper)

    # Global account
    acct = helper.get_arg("global_account") or {}
    username = acct.get("username")
    password = acct.get("password")
    if not username or not password:
        helper.log_error("Missing Global Account. Configure it on the add-on's Configuration page.")
        return

    # Input params
    object_type = (helper.get_arg("object_type") or "users").lower()
    if object_type not in ("users", "hosts", "dns", "certs", "groups", "hbac", "rbac"):
        helper.log_error("Bad object_type: {}".format(object_type))
        return

    helper.log_info("START url={} verify={} object_type={}".format(base_url, verify, object_type))

    s = requests.Session()

    # 1) Login
    try:
        r = s.post(f"{base_url}/ipa/session/login_password",
                   data={"user": username, "password": password},
                   headers={"Referer": base_url + "/ipa",
                            "Accept": "text/plain",
                            "Content-Type": "application/x-www-form-urlencoded"},
                   verify=verify, timeout=30)
        helper.log_info("LOGIN status={}".format(r.status_code))
    except Exception as e:
        helper.log_error("LOGIN_EX: {}".format(repr(e)))
        return

    # 2) env (API version)
    try:
        r = s.post(f"{base_url}/ipa/session/json",
                   json={"method": "env", "params": [[], {}], "id": 0},
                   headers={"Referer": base_url + "/ipa",
                            "Accept": "application/json",
                            "Content-Type": "application/json"},
                   verify=verify, timeout=30)
        env = r.json()
        if env.get("error") not in (None,):
            helper.log_error("ENV_ERR: {}".format(json.dumps(env["error"])))
            return
        api_version = env["result"]["result"].get("api_version") or env["result"].get("version")
        helper.log_info("ENV api_version={}".format(api_version))
    except Exception as e:
        helper.log_error("ENV_EX: {}".format(repr(e)))
        return

    # 3) Dispatch by object_type
    if object_type == "users":
        payload = {"method": "user_find",
                   "params": [[""], {"all": True, "sizelimit": 0, "version": api_version}],
                   "id": 1}

        try:
            r = s.post(f"{base_url}/ipa/session/json",
                       json=payload,
                       headers={"Referer": base_url + "/ipa",
                                "Accept": "application/json",
                                "Content-Type": "application/json"},
                       verify=verify, timeout=120)
            resp = r.json()
            if resp.get("error") not in (None,):
                helper.log_error("RPC_ERR(users): {}".format(json.dumps(resp["error"])))
                return
            results = resp.get("result", {}).get("result", [])
            helper.log_info("RPC_OK type=users count={}".format(len(results)))
            _emit_records(helper, ew, base_url, "users", results)
        except Exception as e:
            helper.log_error("RPC_EX(users): {}".format(repr(e)))
            return

    elif object_type == "hosts":
        payload = {"method": "host_find",
                   "params": [[""], {"all": True, "sizelimit": 0, "version": api_version}],
                   "id": 2}

        try:
            r = s.post(f"{base_url}/ipa/session/json",
                       json=payload,
                       headers={"Referer": base_url + "/ipa",
                                "Accept": "application/json",
                                "Content-Type": "application/json"},
                       verify=verify, timeout=120)
            resp = r.json()
            if resp.get("error") not in (None,):
                helper.log_error("RPC_ERR(hosts): {}".format(json.dumps(resp["error"])))
                return
            results = resp.get("result", {}).get("result", [])
            helper.log_info("RPC_OK type=hosts count={}".format(len(results)))
            _emit_records(helper, ew, base_url, "hosts", results)
        except Exception as e:
            helper.log_error("RPC_EX(hosts): {}".format(repr(e)))
            return

    elif object_type == "dns":
        # Zones
        z_payload = {"method": "dnszone_find",
                     "params": [[""], {"all": True, "sizelimit": 0, "version": api_version}],
                     "id": 300}
        try:
            zr = s.post(f"{base_url}/ipa/session/json",
                        json=z_payload,
                        headers={"Referer": base_url + "/ipa",
                                 "Accept": "application/json",
                                 "Content-Type": "application/json"},
                        verify=verify, timeout=120)
            zdata = zr.json()
            if zdata.get("error") not in (None,):
                helper.log_error("DNS zones rpc error={}".format(json.dumps(zdata["error"])))
                return
            zones = zdata.get("result", {}).get("result", [])
            helper.log_info("DNS zones: {}".format(len(zones)))
            _emit_records(helper, ew, base_url, "dns_zone", zones)
        except Exception as e:
            helper.log_error("DNS_ZONE_RPC_EX: {}".format(repr(e)))
            return

        # Records per zone
        for z in zones:
            zone = _dnsname(z.get("idnsname"))
            if not zone:
                continue
            r_payload = {"method": "dnsrecord_find",
                         "params": [[zone], {"all": True, "sizelimit": 0, "version": api_version}],
                         "id": 301}
            try:
                rr = s.post(f"{base_url}/ipa/session/json",
                            json=r_payload,
                            headers={"Referer": base_url + "/ipa",
                                     "Accept": "application/json",
                                     "Content-Type": "application/json"},
                            verify=verify, timeout=180)
                rdata = rr.json()
                if rdata.get("error") not in (None,):
                    helper.log_warning("DNS records error zone={}: {}".format(zone, json.dumps(rdata["error"])))
                    continue
                recs = rdata.get("result", {}).get("result", [])
                helper.log_info("DNS records zone={} count={}".format(zone, len(recs)))
                _emit_dns_record_events(helper, ew, base_url, zone, recs)
            except Exception as e:
                helper.log_error("DNS_RECORD_EX zone={}: {}".format(zone, repr(e)))
                continue

        helper.log_info("DNS enumeration DONE")
        return

    elif object_type == "groups":
        payload = {"method": "group_find",
                   "params": [[""], {"all": True, "sizelimit": 0, "version": api_version}],
                   "id": 10}
        try:
            r = s.post(f"{base_url}/ipa/session/json",
                       json=payload,
                       headers={"Referer": base_url + "/ipa",
                                "Accept": "application/json",
                                "Content-Type": "application/json"},
                       verify=verify, timeout=180)
            resp = r.json()
            if resp.get("error") not in (None,):
                helper.log_error("RPC_ERR(groups): {}".format(json.dumps(resp["error"])))
                return
            results = resp.get("result", {}).get("result", [])
            helper.log_info("RPC_OK type=groups count={}".format(len(results)))
            _emit_records(helper, ew, base_url, "groups", results)
        except Exception as e:
            helper.log_error("RPC_EX(groups): {}".format(repr(e)))
            return

    elif object_type == "hbac":
        def _rpc(method, pid):
            r = s.post(f"{base_url}/ipa/session/json",
                       json={"method": method, "params": [[""], {"all": True, "sizelimit": 0, "version": api_version}], "id": pid},
                       headers={"Referer": base_url + "/ipa",
                                "Accept": "application/json",
                                "Content-Type": "application/json"},
                       verify=verify, timeout=180)
            j = r.json()
            if j.get("error") not in (None,):
                helper.log_warning(f"RPC_WARN({method}): {json.dumps(j['error'])}")
                return []
            return j.get("result", {}).get("result", []) or []

        rules = _rpc("hbacrule_find", 20)
        svcs  = _rpc("hbacsvc_find", 21)
        svcg  = _rpc("hbacsvcgroup_find", 22)

        helper.log_info(f"HBAC rules={len(rules)} svcs={len(svcs)} svcgroups={len(svcg)}")
        _emit_records(helper, ew, base_url, "hbac_rule", rules)
        _emit_records(helper, ew, base_url, "hbac_service", svcs)
        _emit_records(helper, ew, base_url, "hbac_servicegroup", svcg)
        return

    elif object_type == "rbac":
        def _rpc(method, pid):
            r = s.post(f"{base_url}/ipa/session/json",
                       json={"method": method, "params": [[""], {"all": True, "sizelimit": 0, "version": api_version}], "id": pid},
                       headers={"Referer": base_url + "/ipa",
                                "Accept": "application/json",
                                "Content-Type": "application/json"},
                       verify=verify, timeout=180)
            j = r.json()
            if j.get("error") not in (None,):
                helper.log_warning(f"RPC_WARN({method}): {json.dumps(j['error'])}")
                return []
            return j.get("result", {}).get("result", []) or []

        roles = _rpc("role_find",       30)
        privs = _rpc("privilege_find",  31)
        perms = _rpc("permission_find", 32)

        helper.log_info(f"RBAC roles={len(roles)} privileges={len(privs)} permissions={len(perms)}")
        _emit_records(helper, ew, base_url, "rbac_role", roles)
        _emit_records(helper, ew, base_url, "rbac_privilege", privs)
        _emit_records(helper, ew, base_url, "rbac_permission", perms)
        return

    else:  # certs
        payload = {"method": "cert_find",
                   "params": [[], {"all": True, "sizelimit": 0, "version": api_version}],
                   "id": 4}

        try:
            r = s.post(f"{base_url}/ipa/session/json",
                       json=payload,
                       headers={"Referer": base_url + "/ipa",
                                "Accept": "application/json",
                                "Content-Type": "application/json"},
                       verify=verify, timeout=180)
            resp = r.json()
            if resp.get("error") not in (None,):
                helper.log_error("RPC_ERR(certs): {}".format(json.dumps(resp["error"])))
                return
            results = resp.get("result", {}).get("result", [])
            helper.log_info("RPC_OK type=certs count={}".format(len(results)))
            _emit_records(helper, ew, base_url, "certs", results)
        except Exception as e:
            helper.log_error("RPC_EX(certs): {}".format(repr(e)))
            return

        # Normalized cert summaries
        now = int(time.time())
        for rec in results:
            serial = _first(rec.get("serial_number") or rec.get("serial") or rec.get("serialno"))
            subject = _first(rec.get("subject"))
            issuer  = _first(rec.get("issuer"))
            status  = _first(rec.get("status")) or _first(rec.get("revoked"))
            not_after_raw  = _first(rec.get("valid_not_after")  or rec.get("not_after")  or rec.get("validity_end"))
            not_before_raw = _first(rec.get("valid_not_before") or rec.get("not_before") or rec.get("validity_start"))
            not_after_epoch  = _gtime_to_epoch(not_after_raw)
            not_before_epoch = _gtime_to_epoch(not_before_raw)
            not_after_iso  = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(not_after_epoch)) if not_after_epoch else None
            not_before_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(not_before_epoch)) if not_before_epoch else None
            days_left = round((not_after_epoch - now)/86400, 1) if not_after_epoch else None

            ew.write_event(helper.new_event(
                sourcetype="idm:json",
                time=now,
                data=json.dumps({
                    "idm_server": base_url,
                    "object_type": "certs",
                    "cert_summary": {
                        "serial": serial,
                        "subject": subject,
                        "issuer": issuer,
                        "status": status,
                        "not_before_raw": not_before_raw,
                        "not_after_raw":  not_after_raw,
                        "not_before_epoch": not_before_epoch,
                        "not_after_epoch":  not_after_epoch,
                        "not_before_iso":   not_before_iso,
                        "not_after_iso":    not_after_iso,
                        "days_left":        days_left
                    },
                    "record": rec
                })
            ))

    helper.log_info("DONE")
