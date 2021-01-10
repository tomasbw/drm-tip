// SPDX-License-Identifier: MIT
/*
 * Copyright(c) 2019-2021, Intel Corporation. All rights reserved.
 */

#include <linux/mfd/core.h>
#include <linux/irq.h>
#include "i915_reg.h"
#include "i915_drv.h"
#include "gt/intel_gt.h"
#include "spi/intel_spi.h"

static const struct resource spi_resources[] = {
	DEFINE_RES_MEM_NAMED(GEN12_GUNIT_SPI_BASE, 0x80, "i915-spi-mmio"),
};

static const struct mfd_cell intel_spi_cell = {
	.id = 2,
	.name = "i915-spi",
	.num_resources = ARRAY_SIZE(spi_resources),
	.resources = spi_resources,
};

void intel_spi_init(struct intel_spi *spi, struct drm_i915_private *dev_priv)
{
	struct pci_dev *pdev = dev_priv->drm.pdev;
	int ret;

	/* Only the DGFX devices have internal SPI */
	if (!IS_DGFX(dev_priv))
		return;

	ret = mfd_add_devices(&pdev->dev, PLATFORM_DEVID_AUTO,
			      &intel_spi_cell, 1,
			      &pdev->resource[0], -1, NULL);
	if (ret)
		dev_err(&pdev->dev, "creating i915-spi cell failed\n");

	spi->i915 = dev_priv;
}
