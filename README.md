# cripto-
Cripto de watts

"""SecureChat - núcleo de criptografia."""

import base64
import json
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
ALGORITHM = "X25519+HKDF-SHA256+AES-256-GCM+Ed25519"


class SecureChatError(Exception):
    """Erro base do SecureChat."""


class EnvelopeError(SecureChatError):
    """Envelope de mensagem inválido."""


class AuthenticationError(SecureChatError):
    """Falha na autenticação ou assinatura."""


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise EnvelopeError("Base64 inválido.") from exc


def private_bytes(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_bytes(key) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def generate_identity() -> dict:
    """Gera chaves de identidade para o usuário."""
    agreement_key = x25519.X25519PrivateKey.generate()
    signing_key = ed25519.Ed25519PrivateKey.generate()

    return {
        "version": str(VERSION),
        "agreement_private": b64_encode(private_bytes(agreement_key)),
        "agreement_public": b64_encode(
            public_bytes(agreement_key.public_key())
        ),
        "signing_private": b64_encode(private_bytes(signing_key)),
        "signing_public": b64_encode(
            public_bytes(signing_key.public_key())
        ),
    }


def load_x25519_private(encoded: str):
    raw = b64_decode(encoded)
    if len(raw) != 32:
        raise EnvelopeError("Chave privada X25519 inválida.")
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def load_x25519_public(encoded: str):
    raw = b64_decode(encoded)
    if len(raw) != 32:
        raise EnvelopeError("Chave pública X25519 inválida.")
    return x25519.X25519PublicKey.from_public_bytes(raw)


def load_ed25519_private(encoded: str):
    raw = b64_decode(encoded)
    if len(raw) != 32:
        raise EnvelopeError("Chave privada Ed25519 inválida.")
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def load_ed25519_public(encoded: str):
    raw = b64_decode(encoded)
    if len(raw) != 32:
        raise EnvelopeError("Chave pública Ed25519 inválida.")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Deriva uma chave AES-256 a partir do segredo compartilhado."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"SecureChat message key v1",
    ).derive(shared_secret)


def encrypt_message(
    plaintext: str,
    recipient_public_key: str,
    sender_signing_private_key: str,
    sender_signing_public_key: str,
) -> dict:
    """Criptografa e assina uma mensagem para um destinatário."""
    if not isinstance(plaintext, str):
        raise TypeError("A mensagem deve ser texto.")

    if len(plaintext.encode("utf-8")) > 1_000_000:
        raise ValueError("A mensagem ultrapassa o limite de 1 MB.")

    recipient_key = load_x25519_public(recipient_public_key)
    signing_key = load_ed25519_private(sender_signing_private_key)

    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    shared_secret = ephemeral_private.exchange(recipient_key)
    salt = os.urandom(32)
    nonce = os.urandom(12)
    key = derive_key(shared_secret, salt)

    metadata = {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "ephemeral_public_key": b64_encode(
            public_bytes(ephemeral_public)
        ),
        "salt": b64_encode(salt),
        "nonce": b64_encode(nonce),
        "sender_signing_public_key": sender_signing_public_key,
    }

    associated_data = canonical_json(metadata)

    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        associated_data,
    )

    signed_content = {
        **metadata,
        "ciphertext": b64_encode(ciphertext),
    }

    signature = signing_key.sign(canonical_json(signed_content))

    return {
        **signed_content,
        "signature": b64_encode(signature),
    }


def decrypt_message(
    envelope: dict,
    recipient_private_key: str,
    trusted_sender_public_key: str,
) -> str:
    """Valida a assinatura e descriptografa o envelope recebido."""
    required = {
        "version",
        "algorithm",
        "ephemeral_public_key",
        "salt",
        "nonce",
        "sender_signing_public_key",
        "ciphertext",
        "signature",
    }

    if not isinstance(envelope, dict) or not required.issubset(envelope):
        raise EnvelopeError("Envelope incompleto.")

    if (
        envelope["version"] != VERSION
        or envelope["algorithm"] != ALGORITHM
    ):
        raise EnvelopeError("Versão ou algoritmo não suportado.")

    if envelope["sender_signing_public_key"] != trusted_sender_public_key:
        raise AuthenticationError("Chave do remetente não confiável.")

    metadata = {
        "version": envelope["version"],
        "algorithm": envelope["algorithm"],
        "ephemeral_public_key": envelope["ephemeral_public_key"],
        "salt": envelope["salt"],
        "nonce": envelope["nonce"],
        "sender_signing_public_key": envelope[
            "sender_signing_public_key"
        ],
    }

    signed_content = {
        **metadata,
        "ciphertext": envelope["ciphertext"],
    }

    signing_public = load_ed25519_public(trusted_sender_public_key)

    try:
        signing_public.verify(
            b64_decode(envelope["signature"]),
            canonical_json(signed_content),
        )
    except InvalidSignature as exc:
        raise AuthenticationError("Assinatura digital inválida.") from exc

    nonce = b64_decode(envelope["nonce"])
    salt = b64_decode(envelope["salt"])

    if len(nonce) != 12 or len(salt) != 32:
        raise EnvelopeError("Nonce ou salt com tamanho inválido.")

    recipient_private = load_x25519_private(recipient_private_key)
    ephemeral_public = load_x25519_public(
        envelope["ephemeral_public_key"]
    )

    shared_secret = recipient_private.exchange(ephemeral_public)
    key = derive_key(shared_secret, salt)

    try:
        plaintext = AESGCM(key).decrypt(
            nonce,
            b64_decode(envelope["ciphertext"]),
            canonical_json(metadata),
        )
    except InvalidTag as exc:
        raise AuthenticationError(
            "Mensagem alterada ou chave incorreta."
        ) from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeError("Texto descriptografado inválido.") from exc

"""Interface de linha de comando do SecureChat."""

import argparse
import json
import sys
from pathlib import Path

from .crypto import (
    AuthenticationError,
    EnvelopeError,
    encrypt_message,
    decrypt_message,
    generate_identity,
)


def read_json(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Não foi possível ler {path}: {exc}") from exc


def write_json(path: str, data: dict) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    try:
        destination.chmod(0o600)
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="securechat",
        description="Demonstração de criptografia ponta a ponta.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    identity = commands.add_parser(
        "identity", help="Gerar uma identidade criptográfica"
    )
    identity.add_argument("--out", required=True)

    encrypt = commands.add_parser(
        "encrypt", help="Criptografar e assinar uma mensagem"
    )
    encrypt.add_argument("--to", required=True)
    encrypt.add_argument("--from-identity", required=True)
    encrypt.add_argument("--message", required=True)
    encrypt.add_argument("--out", required=True)

    decrypt = commands.add_parser(
        "decrypt", help="Verificar e descriptografar uma mensagem"
    )
    decrypt.add_argument("--identity", required=True)
    decrypt.add_argument("--trusted-sender-key", required=True)
    decrypt.add_argument("--envelope", required=True)
    decrypt.add_argument("--out")

    args = parser.parse_args()

    try:
        if args.command == "identity":
            write_json(args.out, generate_identity())
            print(f"Identidade criada: {args.out}")

        elif args.command == "encrypt":
            recipient = read_json(args.to)
            sender = read_json(args.from_identity)

            envelope = encrypt_message(
                args.message,
                recipient["agreement_public"],
                sender["signing_private"],
                sender["signing_public"],
            )

            write_json(args.out, envelope)
            print(f"Mensagem criptografada: {args.out}")

        elif args.command == "decrypt":
            recipient = read_json(args.identity)
            envelope = read_json(args.envelope)

            plaintext = decrypt_message(
                envelope,
                recipient["agreement_private"],
                args.trusted_sender_key,
            )

            if args.out:
                Path(args.out).write_text(
                    plaintext, encoding="utf-8"
                )
                print(f"Mensagem salva: {args.out}")
            else:
                print(plaintext)

        return 0

    except (
        ValueError,
        KeyError,
        AuthenticationError,
        EnvelopeError,
    ) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""SecureChat: projeto educacional de mensagens criptografadas."""

__version__ = "1.0.0"

import copy
import unittest

from securechat.crypto import (
    AuthenticationError,
    decrypt_message,
    encrypt_message,
    generate_identity,
)


class SecureChatTests(unittest.TestCase):

    def setUp(self):
        self.alice = generate_identity()
        self.bob = generate_identity()

    def test_encrypt_and_decrypt(self):
        message = "Olá, Bob! Mensagem protegida 🔐"

        envelope = encrypt_message(
            message,
            self.bob["agreement_public"],
            self.alice["signing_private"],
            self.alice["signing_public"],
        )

        result = decrypt_message(
            envelope,
            self.bob["agreement_private"],
            self.alice["signing_public"],
        )

        self.assertEqual(result, message)

    def test_tampered_message_is_rejected(self):
        envelope = encrypt_message(
            "Mensagem secreta",
            self.bob["agreement_public"],
            self.alice["signing_private"],
            self.alice["signing_public"],
        )

        altered = copy.deepcopy(envelope)
        altered["ciphertext"] = "AAAA"

        with self.assertRaises(AuthenticationError):
            decrypt_message(
                altered,
                self.bob["agreement_private"],
                self.alice["signing_public"],
            )

    def test_untrusted_sender_is_rejected(self):
        envelope = encrypt_message(
            "Olá!",
            self.bob["agreement_public"],
            self.alice["signing_private"],
            self.alice["signing_public"],
        )

        other_identity = generate_identity()

        with self.assertRaises(AuthenticationError):
            decrypt_message(
                envelope,
                self.bob["agreement_private"],
                other_identity["signing_public"],
            )


if __name__ == "__main__":
    unittest.main()

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "securechat-e2ee-demo"
version = "1.0.0"
description = "Educational end-to-end encryption messaging demo"
requires-python = ">=3.10"
dependencies = [
    "cryptography>=42.0.0"
]

[project.scripts]
securechat = "securechat.cli:main"

[tool.setuptools.packages.find]
include = ["securechat*"]

__pycache__/
*.py[cod]
.venv/
venv/
.env
*.egg-info/
build/
dist/

# Arquivos de identidade e dados locais
identity*.json
*_identity.json
private*.json
message*.json
envelope*.json

# SecureChat — End-to-End Encryption 🔐

Projeto educacional desenvolvido em Python para demonstrar
conceitos de criptografia ponta a ponta (E2EE).

## Tecnologias

- Python
- X25519 para acordo de chaves
- HKDF-SHA256 para derivação de chaves
- AES-256-GCM para criptografia autenticada
- Ed25519 para assinaturas digitais
- unittest para testes automatizados

## Funcionalidades

- Geração de identidades criptográficas
- Criptografia de mensagens
- Descriptografia para o destinatário correto
- Verificação de assinaturas digitais
- Detecção de mensagens alteradas
- Testes automatizados de segurança básica

## Instalação

Requisitos: Python 3.10 ou superior.

```bash
python -m venv .venv
```

No Windows:

```bash
.venv\Scripts\activate
```

No macOS ou Linux:

```bash
source .venv/bin/activate
```

Instale as dependências:

```bash
python -m pip install -e .
```

## Como utilizar

### 1. Gerar identidades

```bash
securechat identity --out alice_identity.json
securechat identity --out bob_identity.json
```

### 2. Criptografar uma mensagem

```bash
securechat encrypt --to bob_identity.json --from-identity alice_identity.json --message "Olá Bob!" --out envelope.json
```

### 3. Descriptografar a mensagem

Use o valor `signing_public` do arquivo de identidade da Alice
como chave pública confiável do remetente.

```bash
securechat decrypt --identity bob_identity.json --trusted-sender-key "CHAVE_PUBLICA_DA_ALICE" --envelope envelope.json
```

## Executar testes

```bash
python -m unittest discover -s tests -v
```

## Estrutura do projeto

```text
securechat-e2ee/
├── securechat/
│   ├── __init__.py
│   ├── crypto.py
│   └── cli.py
├── tests/
│   └── test_crypto.py
├── .gitignore
├── pyproject.toml
├── README.md
└── LICENSE
```

## Aviso de segurança

Este projeto é uma demonstração educacional, não uma implementação
oficial do WhatsApp ou do Signal Protocol. Não foi auditado e não
deve ser utilizado para proteger informações sensíveis em produção.

As chaves privadas do exemplo são armazenadas sem criptografia
nos arquivos de identidade. Nunca publique esses arquivos.

Uma aplicação real precisa de gestão segura de chaves, prevenção
contra replay, protocolo de sessão completo, revisão independente
e outras proteções adicionais.

## Próximas melhorias

- Criar uma API com FastAPI
- Implementar comunicação em tempo real com WebSockets
- Adicionar banco de dados
- Criar autenticação de usuários
- Desenvolver uma interface de chat

## Licença

MIT
