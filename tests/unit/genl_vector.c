/* SPDX-License-Identifier: GPL-2.0-only */
#include "genl.h"

#include <linux/netlink.h>
#include <stdio.h>

int main(void)
{
    unsigned char buffer[128];
    struct melodi_genl_builder builder;

    if (melodi_genl_begin(&builder, buffer, sizeof(buffer), 0x1234,
                          NLM_F_REQUEST | NLM_F_ACK, 0x10203040,
                          0x55667788, MELODI_CMD_BIND) != 0)
        return 1;
    if (melodi_genl_put_u32(&builder, MELODI_A_IFINDEX, 7) != 0 ||
        melodi_genl_put_u16(&builder, MELODI_A_LOCAL_SERVICE, 42) != 0 ||
        melodi_genl_end(&builder) != 0)
        return 1;
    return fwrite(buffer, builder.length, 1, stdout) == 1 ? 0 : 1;
}
