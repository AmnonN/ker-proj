#include <linux/module.h>   /* Needed by all modules */
#include <linux/net.h>
#include <linux/string.h> // for memcpy
#include <linux/slab.h>   // for kmalloc kfree
#include <linux/uaccess.h>
#include <linux/socket.h>
#include "mysock_action.h"

extern int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size);

struct proto_ops custom_ops;
struct proto_ops original_ops;
static int       header_size;
static char      *header_buff;

int mysock_ioctl(struct socket *sock,
                 unsigned int cmd,
                 unsigned long arg)
{
    printk("mysock_ioctl: arg addr %lu\n", arg);
    //unsigned long header_size;
    switch (cmd)
    {
        case (SET_INITIAL_HEADER):
        {
            printk("mysock_ioctl: setting initial buffer!\n");
            if (header_buff != NULL)
            {
                kfree(header_buff);
            }

            // first 4 bytes of the buffer is the size
            copy_from_user((char*)&header_size, (char*)arg, 4);

            printk("header size is %du", header_size);

            header_buff = kmalloc(header_size, GFP_KERNEL);

            // copy the rest of the header buffer
            copy_from_user(header_buff, ((const char*)arg) + 4, header_size);

            printk("mysock_ioctl: header size : %du ", header_size);

            break;
        }
    }
    return 0;
}

int mysock_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
    struct iovec* nonconst_iovec;

    // Add the header part to the sent data
    total_len += header_size;
    m->msg_iter.count = total_len;
    nonconst_iovec = (struct iovec*)&m->msg_iter.iov[0]; // Removing the const from iovec, shhhh..
    nonconst_iovec->iov_base = header_buff;
    nonconst_iovec->iov_len = header_size;

    return inet_sendmsg(sock, m, total_len);
}

 
static void copy_proto_ops(struct proto_ops *dst, const struct proto_ops *src)
{
     dst->family = src->family;
     dst->owner = src->owner;
     dst->release = src->release;
     dst->bind = src->bind;
     dst->connect = src->connect;
     dst->socketpair = src->socketpair;
     dst->accept = src->accept;
     dst->getname = src->getname;
     dst->poll = src->poll;
     dst->ioctl = src->ioctl;
 
     #ifdef CONFIG_COMPAT
     dst->compat_ioctl = src->compat_ioctl;
     dst->compat_getsockopt = src->compat_getsockopt;
     dst->compat_setsockopt = src->compat_setsockopt;
     #endif
 
     dst->listen = src->listen;
     dst->shutdown = src->shutdown;
     dst->getsockopt = src->getsockopt;
     dst->setsockopt = src->setsockopt;
     dst->sendmsg = src->sendmsg;
     dst->recvmsg = src->recvmsg;
     dst->mmap = src->mmap;
     dst->sendpage = src->sendpage;
     dst->splice_read = src->splice_read;
}

static void copy_socket(struct socket *dst, const struct socket *src)
{
    //unsigned long i;

    // naive memcpy impl
    //for (i = 0; i < sizeof(struct socket); ++i)
    //{
    //    ((char*)dst)[i] = ((const char*)src)[i];
    //}
    memcpy((char*)dst, (char*)src, sizeof(struct socket));
}

static int mysock_create(struct net *net, struct socket *sock, int protocol,
                 int kern)
{
    header_size = 0;
    header_buff = NULL;

    struct socket *temp_sock;
    int ret = sock_create(PF_INET, SOCK_DGRAM, 0, &temp_sock);

    // copy result to the original socket
    copy_socket(sock, temp_sock);

    static int custom_ops_initialized = 0;
    if (!custom_ops_initialized)
    {
         copy_proto_ops(&custom_ops, sock->ops);
         custom_ops_initialized = 1;
    }

    // save the original ops that we are goind to override (ioctl, send, recv)
    original_ops.ioctl = custom_ops.ioctl;
    original_ops.sendmsg = custom_ops.sendmsg;

    // set specific fields of the proto_ops
    custom_ops.family = PF_MYSOCK;
    custom_ops.owner  = THIS_MODULE;
    custom_ops.ioctl = mysock_ioctl;
    custom_ops.sendmsg = mysock_sendmsg;

    sock->ops = &custom_ops;

    return ret;
}
 
static const struct net_proto_family mysock_family_ops = {
     .family         = PF_MYSOCK, // Defined in linux/socket.h after recompiled the kernel
     .owner          = THIS_MODULE,
     .create         = mysock_create
};
 
int init_module(void)
{
    header_buff = NULL;

    int ret = sock_register(&mysock_family_ops);

    if (ret == -ENOBUFS)
    {
        printk("ENOBUFS!\n\n\n\n");
    }
    else if (ret == -EEXIST)
    {
        printk("EEXISTS!\n\n\n\n");
    }
    else if (ret == 0)
    {

        printk("NO ERR!\n\n\n\n");  
    }
    else
    {
        printk("%d\n", ret);
    }

 
    /*
     * A non 0 return means init_module failed; module can't be loaded.
     */
    return 0;
}
 
void cleanup_module(void)
{
    if (header_buff != NULL)
    {
        kfree(header_buff);
    }

    sock_unregister(PF_MYSOCK);
    printk(KERN_INFO "Goodbye world 1.\n");
}