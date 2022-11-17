#
# Copyright(c) 2012-2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

PWD=$(shell pwd)
VERSION_FILE := $(PWD)/../.metadata/cas_version
-include $(VERSION_FILE)

EXTRA_CFLAGS += -DCAS_VERSION=\"$(CAS_VERSION)\"

OCFDIR=$(PWD)/../ocf

sync:
	@$(MAKE) -C ${OCFDIR} inc O=$(PWD)
	@$(MAKE) -C ${OCFDIR} src O=$(PWD)
	@$(MAKE) -C ${OCFDIR} env O=$(PWD) OCF_ENV=posix

distsync:
	@$(MAKE) -C ${OCFDIR} distclean O=$(PWD)

.PHONY: sync distsync
