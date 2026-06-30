# Maintainer: Alexander Baldeck <alex.bldck@gmail.com>
pkgname=apb
pkgver=2026.06.30
pkgrel=1
pkgdesc="Arch Package Builder - A distributed package building system"
arch=('any')
url="https://github.com/kth5/apb"
license=('MIT')
depends=(
  'python'
  'python-fastapi'
  'uvicorn'
  'python-psutil'
  'python-httpx'
  'python-jinja'
  'python-multipart'
)
makedepends=(
  'python-build'
  'python-installer'
  'python-hatchling'
)
optdepends=(
  'devtools: build server support (makechrootpkg)'
  'arch-install-scripts: buildroot creation (mkarchroot)'
)
backup=('etc/apb/apb.json.example')
install=apb.install
source=(
  'pyproject.toml'
  'README.md'
  'LICENSE'
  'apb.json.example'
  'apb.sysusers'
  'apb.tmpfiles'
  'apb.sudoers'
)
sha256sums=(
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
)

prepare() {
  cp -a "$startdir/src" "$srcdir/"
}

build() {
  cd "$srcdir"
  python -m build --wheel --no-isolation
}

package() {
  cd "$srcdir"
  python -m installer --destdir="$pkgdir" dist/*.whl

  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 apb.json.example "$pkgdir/etc/apb/apb.json.example"
  install -Dm644 apb.sysusers "$pkgdir/usr/lib/sysusers.d/apb.conf"
  install -Dm644 apb.tmpfiles "$pkgdir/usr/lib/tmpfiles.d/apb.conf"
  install -Dm750 -d "$pkgdir/etc/sudoers.d"
  install -Dm644 apb.sudoers "$pkgdir/etc/sudoers.d/apb"
}
