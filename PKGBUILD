# Maintainer: Alexander Baldeck <alexander@baldeck.de>
pkgname=apb
pkgver=2025.07.15
pkgrel=1
pkgdesc="Arch Package Builder - A distributed package building system"
arch=('any')
url="https://github.com/yourusername/apb"
license=('MIT')
depends=('python' 'python-fastapi' 'uvicorn' 'python-psutil' 
         'python-aiohttp' 'python-requests' 'python-multipart')
makedepends=()
backup=('etc/apb/apb.json.example')
install=apb.install
source=("apb.py"
        "apb-farm.py" 
        "apb-server.py"
        "apb.json"
        "apb.sysusers"
        "apb.tmpfiles"
        "apb.sudoers")
sha256sums=('SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP')

package() {
    # Install main executables
    install -Dm755 "$srcdir/apb.py" "$pkgdir/usr/bin/apb"
    install -Dm755 "$srcdir/apb-farm.py" "$pkgdir/usr/bin/apb-farm"
    install -Dm755 "$srcdir/apb-server.py" "$pkgdir/usr/bin/apb-server"
    
    # Install configuration example
    install -Dm644 "$srcdir/apb.json" "$pkgdir/etc/apb/apb.json.example"
    
    # Install systemd sysusers configuration
    install -Dm644 "$srcdir/apb.sysusers" "$pkgdir/usr/lib/sysusers.d/apb.conf"
    
    # Install systemd tmpfiles configuration  
    install -Dm644 "$srcdir/apb.tmpfiles" "$pkgdir/usr/lib/tmpfiles.d/apb.conf"
    
    # Install sudoers configuration (commented by default)
    install -Dm750 -d "$pkgdir/etc/sudoers.d"
    install -Dm644 "$srcdir/apb.sudoers" "$pkgdir/etc/sudoers.d/apb"
} 
