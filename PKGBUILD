# Maintainer: Alexander Baldeck <alexander@baldeck.de>
pkgname=apb
pkgver=2026.06.30
pkgrel=1
pkgdesc="Arch Package Builder - A distributed package building system"
arch=('any')
url="https://github.com/yourusername/apb"
license=('MIT')
depends=('python' 'python-fastapi' 'uvicorn' 'python-psutil'
         'python-httpx' 'python-jinja' 'python-multipart')
makedepends=('python-build' 'python-installer' 'python-hatchling')
backup=('etc/apb/apb.json.example')
install=apb.install
source=("pyproject.toml"
        "src"
        "apb.json.example"
        "apb.sysusers"
        "apb.tmpfiles"
        "apb.sudoers")
sha256sums=('SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP')

package() {
    cd "$srcdir"
    python -m installer --destdir="$pkgdir" dist/*.whl

    install -Dm644 "$srcdir/apb.json.example" "$pkgdir/etc/apb/apb.json.example"
    install -Dm644 "$srcdir/apb.sysusers" "$pkgdir/usr/lib/sysusers.d/apb.conf"
    install -Dm644 "$srcdir/apb.tmpfiles" "$pkgdir/usr/lib/tmpfiles.d/apb.conf"
    install -Dm750 -d "$pkgdir/etc/sudoers.d"
    install -Dm644 "$srcdir/apb.sudoers" "$pkgdir/etc/sudoers.d/apb"
}

prepare() {
    cd "$srcdir"
    python -m build -w -n
}
