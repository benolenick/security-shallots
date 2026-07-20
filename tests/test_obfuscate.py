from shallots.ai.obfuscate import Obfuscator

def test_ip_class_and_reversible():
    o = Obfuscator()
    assert o.ip("192.168.0.172").startswith("INT_IP")
    assert o.ip("45.9.148.3").startswith("EXT_IP")
    assert "192.168.0.172" in o.deobfuscate(f"x {o.ip('192.168.0.172')}")

def test_privileged_user_tagged():
    o = Obfuscator()
    assert "privileged" in o.user("root") and "privileged" not in o.user("svc")

def test_unknown_ip_in_prose_masked_without_seeding():
    o = Obfuscator()
    obf = o.obfuscate_alert({"description": "conn from 45.9.148.3 port 22"})
    assert "45.9.148.3" not in obf["description"] and "EXT_IP" in obf["description"]

def test_mac_and_email_in_prose_masked():
    o = Obfuscator()
    obf = o.obfuscate_alert({"raw": "dev aa:bb:cc:dd:ee:ff user admin@corp.example.com"})
    assert "aa:bb:cc:dd:ee:ff" not in obf["raw"] and "admin@corp.example.com" not in obf["raw"]

def test_case_insensitive_and_substring_host():
    o = Obfuscator(); o.seed_assets(hostnames=["mail-server", "host01"])
    obf = o.obfuscate_alert({"title": "login on HOST01 via cloud-vps gateway"})
    assert "host01" not in obf["title"].lower()

def test_strict_failclosed_redacts_any_residue():
    o = Obfuscator(strict=True)
    obf = o.obfuscate_alert({"description": "beacon to 198.51.100.7 and 8.8.4.4"})
    assert "198.51.100.7" not in obf["description"] and "8.8.4.4" not in obf["description"]

def test_verify_catches_leftover():
    o = Obfuscator()
    assert o.verify({"d": "raw 8.8.4.4 here"})  # re-check flags identifier-shaped residue

def test_common_word_not_over_masked():
    o = Obfuscator(); o.seed_assets(hostnames=["host01"])
    obf = o.obfuscate_alert({"description": "received mail about a domain"})
    assert "mail" in obf["description"] and "domain" in obf["description"]
