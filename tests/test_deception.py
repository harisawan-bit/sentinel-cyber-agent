"""Unit tests for Sentinel Defensive Deception, Honeytokens, and Burner Sandbox."""
from __future__ import annotations
import sys, os, tempfile, json, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.deception import (
    generate_decoy_credentials,
    render_decoy_env,
    render_decoy_docker_config,
    render_decoy_ssh_key,
    register_canary_file,
    seed_all_honeytokens,
    CANARY_MANIFEST_PATH,
)
from sentinel.core.honeypot_burner import (
    generate_burner_docker_compose,
    _log_burner_event,
    BURNER_LOG_FILE,
)
from sentinel.core.plugins.canary_audit_plugin import CanaryAuditPlugin


def test_generate_decoy_credentials():
    creds = generate_decoy_credentials(burner_ip="192.168.1.50", burner_ssh_port=2222)
    assert "llm" in creds
    assert "smtp" in creds
    assert "n8n" in creds
    assert "docker" in creds
    assert "remote_access" in creds

    # LLM keys verification
    assert creds["llm"]["OPENAI_API_KEY"].startswith("sk-proj-CANARY_")
    assert creds["llm"]["ANTHROPIC_API_KEY"].startswith("sk-ant-api03-CANARY_")
    assert creds["llm"]["HUGGINGFACE_TOKEN"].startswith("hf_CANARY_")

    # SMTP verification
    assert creds["smtp"]["SMTP_HOST"] == "192.168.1.50"
    assert creds["smtp"]["SMTP_PORT"] == "2525"
    assert creds["smtp"]["SMTP_USER"] == "mailer_service_decoy@internal.local"

    # n8n verification
    assert creds["n8n"]["N8N_API_KEY"].startswith("n8n_api_canary_")
    assert "5678/webhook" in creds["n8n"]["N8N_WEBHOOK_URL"]

    # Docker registry verification
    assert creds["docker"]["DOCKER_REGISTRY"] == "192.168.1.50:5000"
    assert creds["docker"]["DOCKER_USER"] == "ci_runner_decoy"

    # Remote access SSH verification
    assert creds["remote_access"]["SSH_PORT"] == "2222"
    assert creds["remote_access"]["SSH_USER"] == "backup_operator"


def test_render_decoy_configs():
    creds = generate_decoy_credentials()
    
    # 1. .env render
    env_content = render_decoy_env(creds)
    assert f"OPENAI_API_KEY={creds['llm']['OPENAI_API_KEY']}" in env_content
    assert f"N8N_API_KEY={creds['n8n']['N8N_API_KEY']}" in env_content
    assert f"SMTP_PASS={creds['smtp']['SMTP_PASS']}" in env_content

    # 2. Docker config render
    docker_content = render_decoy_docker_config(creds)
    docker_json = json.loads(docker_content)
    assert creds["docker"]["DOCKER_REGISTRY"] in docker_json["auths"]

    # 3. SSH key render
    priv_key, pub_key = render_decoy_ssh_key()
    assert "BEGIN OPENSSH PRIVATE KEY" in priv_key
    assert "ssh-ed25519" in pub_key


def test_seed_honeytokens_and_manifest():
    with tempfile.TemporaryDirectory() as tmp_dir:
        seeded = seed_all_honeytokens(target_dir=tmp_dir)
        assert len(seeded) == 3

        env_file = os.path.join(tmp_dir, ".env.staging.canary")
        docker_file = os.path.join(tmp_dir, "docker-config.json.canary")
        ssh_file = os.path.join(tmp_dir, "id_rsa_backup.canary")

        assert os.path.isfile(env_file)
        assert os.path.isfile(docker_file)
        assert os.path.isfile(ssh_file)

        # Check canary manifest was updated
        assert os.path.isfile(CANARY_MANIFEST_PATH)
        with open(CANARY_MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        paths = [m["path"] for m in manifest]
        assert os.path.abspath(env_file) in paths


def test_canary_tampering_detection():
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_canary = os.path.join(tmp_dir, "test_token.canary")
        with open(test_canary, "w", encoding="utf-8") as f:
            f.write("ORIGINAL_CANARY_SECRET_DATA")

        entry = register_canary_file(test_canary, category="test_token")
        assert entry["baseline_hash"] is not None

        # Verify pristine state detection
        plugin = CanaryAuditPlugin()
        findings = list(plugin.run("localhost", None))
        armed = next((f for f in findings if test_canary in f.value and f.severity == "info"), None)
        assert armed is not None

        # Simulate tampering
        with open(test_canary, "a", encoding="utf-8") as f:
            f.write("\nTAMPERED_INJECTED_DATA")

        findings_after = list(plugin.run("localhost", None))
        tampered = next((f for f in findings_after if test_canary in f.value and f.severity == "critical"), None)
        assert tampered is not None
        assert "tampered with or modified" in tampered.detail
        assert tampered.metadata["threat_category"] == "deception_compromise"


def test_burner_docker_compose_generation():
    compose = generate_burner_docker_compose(
        ssh_port=2222,
        smtp_port=2525,
        n8n_port=5678,
        memory_limit="32m",
        cpu_limit="0.05"
    )
    assert 'memory: 32m' in compose
    assert "cpus: '0.05'" in compose
    assert "read_only: true" in compose
    assert "cap_drop:\n      - ALL" in compose
    assert "no-new-privileges:true" in compose
    assert '"127.0.0.1:2222:2222"' in compose
    assert '"127.0.0.1:2525:2525"' in compose
    assert '"127.0.0.1:5678:5678"' in compose


def test_burner_trap_logging_and_alert():
    _log_burner_event(
        service="SSH_DECOY",
        remote_ip="203.0.113.195",
        remote_port=48123,
        raw_data="USER root PASSWORD hacked"
    )
    assert os.path.isfile(BURNER_LOG_FILE)

    plugin = CanaryAuditPlugin()
    findings = list(plugin.run("localhost", None))
    burner_finding = next((f for f in findings if "203.0.113.195" in f.value), None)

    assert burner_finding is not None
    assert burner_finding.severity == "critical"
    assert "SSH_DECOY" in burner_finding.value
    assert "iptables -I INPUT -s 203.0.113.195 -j DROP" in burner_finding.metadata["iptables_ban"]


if __name__ == "__main__":
    test_generate_decoy_credentials()
    print("PASS test_generate_decoy_credentials")
    test_render_decoy_configs()
    print("PASS test_render_decoy_configs")
    test_seed_honeytokens_and_manifest()
    print("PASS test_seed_honeytokens_and_manifest")
    test_canary_tampering_detection()
    print("PASS test_canary_tampering_detection")
    test_burner_docker_compose_generation()
    print("PASS test_burner_docker_compose_generation")
    test_burner_trap_logging_and_alert()
    print("PASS test_burner_trap_logging_and_alert")
    print("ALL DECEPTION TESTS PASSED")
