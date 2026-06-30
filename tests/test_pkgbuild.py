"""Tests for shared APB library modules."""

from pathlib import Path

from apb.pkgbuild import parse_pkgbuild


def test_parse_pkgbuild_basic():
    content = """
pkgname='hello'
pkgver=1.2.3
pkgrel=4
arch=('x86_64' 'aarch64')
"""
    info = parse_pkgbuild(content)
    assert info.pkgname == "hello"
    assert info.pkgver == "1.2.3"
    assert info.pkgrel == "4"
    assert info.arch == ["x86_64", "aarch64"]


def test_parse_pkgbuild_pkgbase_and_extra_repos():
    content = """
pkgbase=foo
pkgname=('foo' 'foo-docs')
pkgver=2.0.0
pkgrel=1
apb_extra_repos=('custom')
"""
    info = parse_pkgbuild(content)
    assert info.pkgname == "foo"
    assert info.pkgname_list == ["foo", "foo-docs"]
    assert info.extra_repos == ["custom"]


def test_parse_pkgbuild_file(tmp_path: Path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname='testpkg'\npkgver=1.0.0\npkgrel=1\narch=('any')\n", encoding="utf-8")
    from apb.pkgbuild import parse_pkgbuild_file

    info = parse_pkgbuild_file(pkgbuild)
    assert info.pkgname == "testpkg"
    assert info.arch == ["any"]


def test_parse_pkgbuild_variable_substitution():
    content = """
_mod=tdeadmin
_minor=1

pkgname="tde-${_mod}"
pkgver="14.1.$_minor"
pkgrel=1
"""
    info = parse_pkgbuild(content)
    assert info.pkgname == "tde-tdeadmin"
    assert info.pkgver == "14.1.1"


def test_parse_pkgbuild_variable_substitution_unquoted():
    content = """
_minor=2
pkgver=3.0.$_minor
"""
    info = parse_pkgbuild(content)
    assert info.pkgver == "3.0.2"


def test_parse_pkgbuild_variable_substitution_single_quoted():
    content = """
_minor=2
pkgver='3.0.$_minor'
"""
    info = parse_pkgbuild(content)
    assert info.pkgver == "3.0.$_minor"


def test_parse_pkgbuild_variable_substitution_order():
    content = """
pkgname="tde-${_mod}"
_mod=tdeadmin
"""
    info = parse_pkgbuild(content)
    assert info.pkgname == "tde-"


def test_parse_pkgbuild_variable_substitution_pkgname_array():
    content = """
_mod=docs
pkgname=("foo" "foo-${_mod}")
pkgver=1.0.0
"""
    info = parse_pkgbuild(content)
    assert info.pkgname_list == ["foo", "foo-docs"]
    assert info.pkgname == "foo"
