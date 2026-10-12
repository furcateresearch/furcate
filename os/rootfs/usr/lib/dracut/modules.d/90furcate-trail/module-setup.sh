#!/bin/sh
# The boot trail in the initrd: /usr/libexec/furcate-os/breadcrumb run when
# the initrd starts and again once / and /usr are mounted. Included only when
# named (dracut --add furcate-trail).
check() { return 255; }
depends() { echo systemd; }
installkernel() { instmods vfat nls_cp437 nls_iso8859_1 nls_ascii; }
install() {
    inst_multiple mountpoint od tr sed tail awk readlink mktemp mount umount sync sleep date mv rmdir
    inst_script /usr/libexec/furcate-os/breadcrumb /usr/libexec/furcate-os/breadcrumb
    inst_simple "$moddir/furcate-trail-initrd.service" "$systemdsystemunitdir/furcate-trail-initrd.service"
    inst_simple "$moddir/furcate-trail-root.service" "$systemdsystemunitdir/furcate-trail-root.service"
    $SYSTEMCTL -q --root "$initdir" enable furcate-trail-initrd.service furcate-trail-root.service
}
