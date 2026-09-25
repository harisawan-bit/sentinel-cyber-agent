"""Defensive Deception Engine: Honeytokens & Decoy Credentials Generator.

Generates realistic decoy credentials and configuration files:
- LLM / AI API keys (OpenAI, Anthropic, HuggingFace)
- SMTP credentials & mail configurations
- n8n workflow automation API keys and webhook URLs
- Docker registry authentication configs
- Remote access SSH canary keys pointing to isolated burner traps

Registers generated canary files in ~/.sentinel/canaries.json for active
tamper and read access monitoring by CanaryAuditPlugin.
"""
from __future__ import annotations
import hashlib, json, os, secrets, time
from typing import Dict, Any, List, Tuple

CANARY_MANIFEST_PATH = os.path.expanduser("~/.sentinel/canaries.json")


def _generate_synthetic_token(prefix: str, length: int = 32) -> str:
    """Generate high-entropy realistic string with synthetic signature."""
    random_hex = secrets.token_hex(length // 2)
    return f"{prefix}{random_hex}"


def generate_decoy_credentials(burner_ip: str = "127.0.0.1", burner_ssh_port: int = 2222) -> Dict[str, Dict[str, str]]:
    """Synthesize high-fidelity decoy credentials for LLM, SMTP, n8n, Docker, and SSH."""
    return {
        "llm": {
            "OPENAI_API_KEY": _generate_synthetic_token("sk-proj-CANARY_", 40),
            "ANTHROPIC_API_KEY": _generate_synthetic_token("sk-ant-api03-CANARY_", 48),
            "HUGGINGFACE_TOKEN": _generate_synthetic_token("hf_CANARY_", 34),
        },
        "smtp": {
            "SMTP_HOST": burner_ip,
            "SMTP_PORT": "2525",
            "SMTP_USER": "mailer_service_decoy@internal.local",
            "SMTP_PASS": _generate_synthetic_token("SmtpSecret_", 24),
            "MAIL_FROM": "notifications@internal.local",
        },
        "n8n": {
            "N8N_API_KEY": _generate_synthetic_token("n8n_api_canary_", 36),
            "N8N_WEBHOOK_URL": f"http://{burner_ip}:5678/webhook/canary-trigger",
            "N8N_ENCRYPTION_KEY": _generate_synthetic_token("n8n_enc_", 32),
        },
        "docker": {
            "DOCKER_REGISTRY": f"{burner_ip}:5000",
            "DOCKER_USER": "ci_runner_decoy",
            "DOCKER_PASSWORD": _generate_synthetic_token("dckr_pat_", 32),
        },
        "remote_access": {
            "SSH_HOST": burner_ip,
            "SSH_PORT": str(burner_ssh_port),
            "SSH_USER": "backup_operator",
            "SSH_CANARY_NOTE": "Points to isolated burner sandbox with zero production access",
        },
    }


def render_decoy_env(creds: Dict[str, Dict[str, str]]) -> str:
    """Render a comprehensive .env configuration file populated with canary credentials."""
    lines = [
        "# ====================================================================",
        "# Staging Environment Configuration (Internal Microservices)",
        "# Generated for local development and workflow integration",
        "# ====================================================================",
        "",
        "# --- Large Language Model (LLM) Integration ---",
        f"OPENAI_API_KEY={creds['llm']['OPENAI_API_KEY']}",
        f"ANTHROPIC_API_KEY={creds['llm']['ANTHROPIC_API_KEY']}",
        f"HUGGINGFACE_TOKEN={creds['llm']['HUGGINGFACE_TOKEN']}",
        "",
        "# --- Internal SMTP Notification Gateway ---",
        f"SMTP_HOST={creds['smtp']['SMTP_HOST']}",
        f"SMTP_PORT={creds['smtp']['SMTP_PORT']}",
        f"SMTP_USER={creds['smtp']['SMTP_USER']}",
        f"SMTP_PASS={creds['smtp']['SMTP_PASS']}",
        f"MAIL_FROM={creds['smtp']['MAIL_FROM']}",
        "",
        "# --- n8n Workflow Automation Engine ---",
        f"N8N_API_KEY={creds['n8n']['N8N_API_KEY']}",
        f"N8N_WEBHOOK_URL={creds['n8n']['N8N_WEBHOOK_URL']}",
        f"N8N_ENCRYPTION_KEY={creds['n8n']['N8N_ENCRYPTION_KEY']}",
        "",
        "# --- Docker Staging Registry ---",
        f"DOCKER_REGISTRY={creds['docker']['DOCKER_REGISTRY']}",
        f"DOCKER_USER={creds['docker']['DOCKER_USER']}",
        f"DOCKER_PASSWORD={creds['docker']['DOCKER_PASSWORD']}",
        "",
        "# --- Automated Backup Remote Host ---",
        f"REMOTE_BACKUP_HOST={creds['remote_access']['SSH_HOST']}",
        f"REMOTE_BACKUP_PORT={creds['remote_access']['SSH_PORT']}",
        f"REMOTE_BACKUP_USER={creds['remote_access']['SSH_USER']}",
        "",
    ]
    return "\n".join(lines)


def render_decoy_docker_config(creds: Dict[str, Dict[str, str]]) -> str:
    """Render a realistic ~/.docker/config.json with decoy registry credentials."""
    import base64
    user = creds["docker"]["DOCKER_USER"]
    pw = creds["docker"]["DOCKER_PASSWORD"]
    auth_str = base64.b64encode(f"{user}:{pw}".encode()).decode()
    reg = creds["docker"]["DOCKER_REGISTRY"]

    doc = {
        "auths": {
            reg: {
                "auth": auth_str
            }
        },
        "HttpHeaders": {
            "User-Agent": "Docker-Client/24.0.5"
        }
    }
    return json.dumps(doc, indent=2)


def render_decoy_ssh_key() -> Tuple[str, str]:
    """Generate a dummy non-functional OpenSSH private key header."""
    dummy_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "QyNTUxOQAAACACANARY_CANARY_CANARY_CANARY_CANARY_CANARY_AAAABAm/dummy\n"
        "CANARYTOKEN_SENTINEL_DECEPTION_TRIPWIRE_CANARY_CANARY_CANARY_CANARY_01\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    dummy_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICANARY_CANARY_DECOY_KEY sentinel_canary@internal"
    return dummy_key, dummy_pub


def register_canary_file(file_path: str, category: str = "generic") -> Dict[str, Any]:
    """Register a file in ~/.sentinel/canaries.json with cryptographic baseline."""
    os.makedirs(os.path.dirname(CANARY_MANIFEST_PATH), exist_ok=True)
    manifest: List[Dict[str, Any]] = []

    if os.path.exists(CANARY_MANIFEST_PATH):
        try:
            with open(CANARY_MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            manifest = []

    abs_path = os.path.abspath(file_path)
    # Remove existing entry for same path if present
    manifest = [m for m in manifest if m.get("path") != abs_path]

    h = hashlib.sha256()
    with open(abs_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    base_hash = h.hexdigest()

    st = os.stat(abs_path)
    entry = {
        "path": abs_path,
        "category": category,
        "created_at": time.time(),
        "baseline_hash": base_hash,
        "baseline_atime": st.st_atime,
    }
    manifest.append(entry)

    with open(CANARY_MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return entry


def seed_all_honeytokens(target_dir: str = ".") -> List[Dict[str, Any]]:
    """Seed comprehensive honeytokens: .env, docker config, and SSH canary key."""
    os.makedirs(target_dir, exist_ok=True)
    creds = generate_decoy_credentials()
    registered = []

    # 1. Decoy .env file
    env_path = os.path.join(target_dir, ".env.staging.canary")
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(render_decoy_env(creds))
    registered.append(register_canary_file(env_path, category="env_credentials"))

    # 2. Decoy Docker config
    docker_path = os.path.join(target_dir, "docker-config.json.canary")
    with open(docker_path, "w", encoding="utf-8") as f:
        f.write(render_decoy_docker_config(creds))
    registered.append(register_canary_file(docker_path, category="docker_auth"))

    # 3. Decoy SSH key
    ssh_priv, _ = render_decoy_ssh_key()
    ssh_path = os.path.join(target_dir, "id_rsa_backup.canary")
    with open(ssh_path, "w", encoding="utf-8") as f:
        f.write(ssh_priv)
    registered.append(register_canary_file(ssh_path, category="ssh_private_key"))

    return registered
