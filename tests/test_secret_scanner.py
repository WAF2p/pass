"""Tests for the secret scanner placeholder / false-positive handling."""

from __future__ import annotations

from pathlib import Path

from wafpass.secret_scanner import scan_secrets


def _write_and_scan(tmp_path: Path, content: str) -> list:
    tf = tmp_path / "main.tf"
    tf.write_text(content, encoding="utf-8")
    return scan_secrets([tf])


def test_skips_variable_references(tmp_path: Path) -> None:
    findings = _write_and_scan(
        tmp_path,
        '''resource "aws_db_instance" "db" {
           password = var.db_password
           username = local.db_user
           api_key  = module.vault.api_key
        }''',
    )
    assert not findings


def test_skips_data_and_secretsmanager_references(tmp_path: Path) -> None:
    findings = _write_and_scan(
        tmp_path,
        '''resource "aws_db_instance" "db" {
           password = data.aws_secretsmanager_secret_version.db.secret_string
           api_key  = data.azurerm_key_vault_secret.key.value
        }''',
    )
    assert not findings


def test_skips_common_placeholders(tmp_path: Path) -> None:
    content = '''
        resource "x" "y" {
          password    = "placeholder"
          api_key     = "your_api_key_here"
          secret      = "replace_me"
          token       = "changeme"
          db_password = "dummy"
          conn_str    = "notset"
        }
    '''
    findings = _write_and_scan(tmp_path, content)
    assert not findings


def test_skips_known_aws_example_literals(tmp_path: Path) -> None:
    findings = _write_and_scan(
        tmp_path,
        '''locals {
           access_key = "AKIAIOSFODNN7EXAMPLE"
           secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }''',
    )
    assert not findings


def test_skips_common_fake_passwords(tmp_path: Path) -> None:
    findings = _write_and_scan(
        tmp_path,
        '''resource "x" "y" {
          password = "password123"
          admin_pw = "P@ssw0rd"
          token    = "qwerty"
        }''',
    )
    assert not findings


def test_skips_repetitive_and_sequence_values(tmp_path: Path) -> None:
    findings = _write_and_scan(
        tmp_path,
        '''resource "x" "y" {
          password = "aaaaaaaa"
          pin      = "12345678"
          passphrase = "qwerty"
        }''',
    )
    assert not findings


def test_skips_angular_bracket_placeholders(tmp_path: Path) -> None:
    findings = _write_and_scan(
        tmp_path,
        '''resource "x" "y" {
          password = "<REPLACE_ME>"
          api_key  = "<YOUR_API_KEY>"
        }''',
    )
    assert not findings


def test_flags_real_secret_values(tmp_path: Path) -> None:
    findings = _write_and_scan(
        tmp_path,
        '''resource "x" "y" {
          password    = "hK9#mP2$vL5nQ8"
          api_key     = "live_sk_1234567890abcdef"
          secret_key  = "super_secret_value_12345"
        }''',
    )
    assert len(findings) == 3
    assert {f.matched_key for f in findings} == {"password", "api_key", "secret_key"}
