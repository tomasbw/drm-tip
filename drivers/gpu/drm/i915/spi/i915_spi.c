// SPDX-License-Identifier: MIT
/*
 * Copyright(c) 2019-2021, Intel Corporation. All rights reserved.
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/io.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <spi/intel_spi.h>

struct i915_spi {
	void __iomem *base;
	size_t size;
	unsigned int nregions;
	struct {
		const char *name;
		u8 id;
		u64 offset;
		u64 size;
	} regions[];
};

static int i915_spi_probe(struct platform_device *platdev)
{
	struct resource *bar;
	struct device *device;
	struct i915_spi *spi;
	struct i915_spi_region *regions;
	unsigned int nregions;
	unsigned int i, n;
	size_t size;
	char *name;
	size_t name_size;

	device = &platdev->dev;

	regions = dev_get_platdata(&platdev->dev);
	if (!regions) {
		dev_err(device, "no regions defined\n");
		return -ENODEV;
	}

	/* count available regions */
	for (nregions = 0, i = 0; i < I915_SPI_REGIONS; i++) {
		if (regions[i].name)
			nregions++;
	}

	if (!nregions) {
		dev_err(device, "no regions defined\n");
		return -ENODEV;
	}

	size = sizeof(*spi) + sizeof(spi->regions[0]) * nregions;
	spi = devm_kzalloc(device, size, GFP_KERNEL);
	if (!spi)
		return -ENOMEM;

	spi->nregions = nregions;
	for (n = 0, i = 0; i < I915_SPI_REGIONS; i++) {
		if (regions[i].name) {
			name_size = strlen(dev_name(&platdev->dev)) +
				    strlen(regions[i].name) + 2; /* for point */
			name = devm_kzalloc(device, name_size, GFP_KERNEL);
			if (!name)
				continue;
			snprintf(name, name_size, "%s.%s",
				 dev_name(&platdev->dev), regions[i].name);
			spi->regions[n].name = name;
			spi->regions[n].id = i;
			n++;
		}
	}

	bar = platform_get_resource(platdev, IORESOURCE_MEM, 0);
	if (!bar)
		return -ENODEV;

	spi->base = devm_ioremap_resource(device, bar);
	if (IS_ERR(spi->base)) {
		dev_err(device, "mmio not mapped\n");
		return PTR_ERR(spi->base);
	}

	platform_set_drvdata(platdev, spi);

	dev_dbg(device, "i915-spi is bound\n");

	return 0;
}

static int i915_spi_remove(struct platform_device *platdev)
{
	platform_set_drvdata(platdev, NULL);

	return 0;
}

MODULE_ALIAS("platform:i915-spi");
static struct platform_driver i915_spi_driver = {
	.probe  = i915_spi_probe,
	.remove = i915_spi_remove,
	.driver = {
		.name = "i915-spi",
	},
};

module_platform_driver(i915_spi_driver);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel DGFX SPI driver");
