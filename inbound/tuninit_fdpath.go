// +build linux,cgo

package inbound

/*
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int recvFD(_GoString_ fdpath) {
	int fd = -1;
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        goto end;
    }

    struct sockaddr_un local;
	if (fdpath.n > sizeof(local.sun_path) - 1) {
		goto end;
	}
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    strncpy(local.sun_path, fdpath.p, fdpath.n);

    unlink(local.sun_path);
    if (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0) {
        goto end1;
    }
    if (listen(sock, 2) < 0) {
        goto end1;
    }

    struct sockaddr_un remote;
    socklen_t remote_size = sizeof(remote);
    int conn = accept(sock, (struct sockaddr *) &remote, &remote_size);
    if (conn < 0) {
        goto end1;
    }

    struct msghdr msg;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

	struct iovec iov;
    char iov_base;
    iov.iov_base = &iov_base;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

	char control[CMSG_SPACE(sizeof(int))];
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    if (recvmsg(conn, &msg, 0) < 0) {
        goto end2;
    }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int)) || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        goto end2;
    }
    fd = *((int *) CMSG_DATA(cmsg));

end2:
    close(conn);
end1:
    close(sock);
end:
    if (fd >= 0) {
        return fd;
    } else {
        return -errno;
    }
}
*/
import "C"

import (
	"errors"
	"net/url"
	"strconv"
)

func NewTunInbound(u *url.URL) (*tunInbound, error) {
	fdpath := u.Query().Get("fdpath")
	if len(fdpath) == 0 {
		return newTunInboundWithDevice(u)
	}

	fd := int(C.recvFD(fdpath))
	if fd < 0 {
		return nil, errors.New("failed to get fd from " + fdpath + ", errno=" + strconv.Itoa(-fd))
	}
	return newTunInboundWithFD(u, fd, strconv.Itoa(fd))
}
